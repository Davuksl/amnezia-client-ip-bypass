package warptransport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
)

type underlayConfiguration struct {
	ServerHost    string `json:"underlayServerHost"`
	ServerAddress string `json:"underlayServerAddress"`
	AWG           struct {
		PrivateKey string `json:"client_priv_key"`
		PublicKey  string `json:"server_pub_key"`
		Address    string `json:"client_ip"`
		Endpoint   string `json:"hostName"`
		Port       int    `json:"port"`
		InitPacket string `json:"I1"`
	} `json:"awg_config_data"`
}

type relayRequest struct {
	network string
	remote  netip.AddrPort
	apply   func(int)
}

type transportPlan struct {
	configuration map[string]any
	relays        []relayRequest
	targets       map[string]netip.AddrPort
	xray          map[string]any
	xrayTag       string
	username      string
	password      string
	underlay      underlayConfiguration
}

var errInvalidConfiguration = errors.New("invalid WARP transport configuration")

func parsePlan(underlayJSON, protocol string, configurationJSON string) (*transportPlan, error) {
	plan := &transportPlan{targets: make(map[string]netip.AddrPort)}
	if json.Unmarshal([]byte(underlayJSON), &plan.underlay) != nil ||
		json.Unmarshal([]byte(configurationJSON), &plan.configuration) != nil || plan.configuration == nil {
		return nil, errInvalidConfiguration
	}
	if _, err := plan.underlay.uapi(nil, plan.underlay.AWG.Port); err != nil {
		return nil, err
	}
	var err error
	switch strings.ToLower(protocol) {
	case "wireguard", "awg":
		err = plan.prepareWireguard()
	case "openvpn":
		err = plan.prepareOpenVPN()
	case "xray", "ssxray":
		err = plan.prepareXray()
	default:
		err = errInvalidConfiguration
	}
	if err != nil || len(plan.targets) == 0 {
		return nil, errInvalidConfiguration
	}
	return plan, nil
}

func (config underlayConfiguration) uapi(targets map[string]netip.AddrPort, port int) (string, error) {
	privateKey, privateError := base64.StdEncoding.Strict().DecodeString(config.AWG.PrivateKey)
	publicKey, publicError := base64.StdEncoding.Strict().DecodeString(config.AWG.PublicKey)
	address, addressError := netip.ParseAddr(strings.Split(config.AWG.Address, "/")[0])
	endpoint, endpointError := netip.ParseAddr(config.AWG.Endpoint)
	if privateError != nil || publicError != nil || len(privateKey) != 32 || len(publicKey) != 32 ||
		addressError != nil || !address.Is4() || endpointError != nil || !endpoint.Is4() ||
		port < 1 || port > 65535 || !strings.HasPrefix(config.AWG.InitPacket, "<b 0x") ||
		!strings.HasSuffix(config.AWG.InitPacket, ">") || strings.ContainsAny(config.AWG.InitPacket, "\r\n") {
		return "", errInvalidConfiguration
	}
	packet := strings.TrimSuffix(strings.TrimPrefix(config.AWG.InitPacket, "<b 0x"), ">")
	if decoded, err := hex.DecodeString(packet); err != nil || len(decoded) == 0 {
		return "", errInvalidConfiguration
	}
	lines := []string{
		"private_key=" + hex.EncodeToString(privateKey),
		"jc=120", "jmin=23", "jmax=911", "s1=0", "s2=0", "h1=1", "h2=2", "h3=3", "h4=4",
		"i1=" + config.AWG.InitPacket,
		"replace_peers=true", "public_key=" + hex.EncodeToString(publicKey),
		"endpoint=" + net.JoinHostPort(endpoint.String(), strconv.Itoa(port)), "persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
	}
	seen := make(map[netip.Addr]bool)
	for _, target := range targets {
		if !seen[target.Addr()] {
			seen[target.Addr()] = true
			lines = append(lines, "allowed_ip="+target.Addr().String()+"/32")
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func (plan *transportPlan) target(host string, port int) (netip.AddrPort, error) {
	if host == "" || port < 1 || port > 65535 {
		return netip.AddrPort{}, errInvalidConfiguration
	}
	address, err := netip.ParseAddr(host)
	if err != nil && strings.EqualFold(host, plan.underlay.ServerHost) {
		address, err = netip.ParseAddr(plan.underlay.ServerAddress)
	}
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		addresses, lookupError := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if lookupError != nil || len(addresses) == 0 {
			return netip.AddrPort{}, errInvalidConfiguration
		}
		address = addresses[0].Unmap()
	}
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return netip.AddrPort{}, errInvalidConfiguration
	}
	target := netip.AddrPortFrom(address, uint16(port))
	plan.targets[net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))] = target
	plan.targets[target.String()] = target
	return target, nil
}

func (plan *transportPlan) prepareWireguard() error {
	host, _ := plan.configuration["hostName"].(string)
	port, err := configurationPort(plan.configuration["port"])
	if err != nil {
		return err
	}
	target, err := plan.target(host, port)
	if err != nil {
		return err
	}
	plan.relays = append(plan.relays, relayRequest{"udp", target, func(port int) {
		plan.configuration["hostName"] = "127.0.0.1"
		plan.configuration["port"] = port
		plan.configuration["mtu"] = smallerMTU(plan.configuration["mtu"])
	}})
	return nil
}

func configurationPort(value any) (int, error) {
	port, ok := value.(float64)
	if !ok || port < 1 || port > 65535 || math.Trunc(port) != port {
		return 0, errInvalidConfiguration
	}
	return int(port), nil
}

func smallerMTU(value any) string {
	mtu, err := strconv.Atoi(fmt.Sprint(value))
	if err != nil || mtu <= 0 || mtu > 1280 {
		return "1280"
	}
	return strconv.Itoa(mtu)
}

func openVPNFields(line string) ([]string, error) {
	var result []string
	var token strings.Builder
	var quote rune
	escaped := false
	started := false
	for _, character := range strings.TrimSpace(line) {
		if escaped {
			token.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				token.WriteRune(character)
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote, started = character, true
			continue
		}
		if (character == '#' || character == ';') && !started {
			break
		}
		if character == ' ' || character == '\t' || character == '\r' {
			if started {
				result = append(result, token.String())
				token.Reset()
				started = false
			}
			continue
		}
		token.WriteRune(character)
		started = true
	}
	if quote != 0 || escaped {
		return nil, errInvalidConfiguration
	}
	if started {
		result = append(result, token.String())
	}
	return result, nil
}

func (plan *transportPlan) prepareOpenVPN() error {
	text, _ := plan.configuration["config"].(string)
	lines := strings.Split(text, "\n")
	fields := make([][]string, len(lines))
	block := ""
	globalProtocol := "udp"
	globalPort := 1194
	connection := false
	connectionStart := -1
	connectionProtocols := make(map[int]string)
	connectionPorts := make(map[int]int)
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if block != "" {
			if trimmed == "</"+block+">" {
				block = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") &&
			trimmed != "<connection>" && trimmed != "</connection>" {
			block = strings.TrimSuffix(strings.TrimPrefix(trimmed, "<"), ">")
			continue
		}
		values, err := openVPNFields(line)
		if err != nil {
			return err
		}
		fields[index] = values
		if len(values) == 0 {
			continue
		}
		values[0] = strings.TrimPrefix(values[0], "--")
		if values[0] == "<connection>" {
			if connection {
				return errInvalidConfiguration
			}
			connection, connectionStart = true, index
		} else if values[0] == "</connection>" {
			if !connection {
				return errInvalidConfiguration
			}
			connection = false
		} else if values[0] == "proto" {
			if len(values) != 2 {
				return errInvalidConfiguration
			}
			if connection {
				connectionProtocols[connectionStart] = values[1]
			} else {
				globalProtocol = values[1]
			}
		} else if values[0] == "port" || values[0] == "rport" {
			if len(values) != 2 {
				return errInvalidConfiguration
			}
			port, err := strconv.Atoi(values[1])
			if err != nil || port < 1 || port > 65535 {
				return errInvalidConfiguration
			}
			if connection {
				connectionPorts[connectionStart] = port
			} else {
				globalPort = port
			}
		}
		if values[0] == "http-proxy" || values[0] == "socks-proxy" || values[0] == "config" {
			return errInvalidConfiguration
		}
	}
	if block != "" || connection {
		return errInvalidConfiguration
	}
	protocol := globalProtocol
	defaultPort := globalPort
	for index, values := range fields {
		if len(values) == 0 {
			continue
		}
		if values[0] == "<connection>" {
			protocol = connectionProtocols[index]
			if protocol == "" {
				protocol = globalProtocol
			}
			defaultPort = connectionPorts[index]
			if defaultPort == 0 {
				defaultPort = globalPort
			}
		} else if values[0] == "</connection>" {
			protocol = globalProtocol
			defaultPort = globalPort
		}
		if values[0] == "local" || values[0] == "remote-random-hostname" {
			lines[index] = ""
		}
		if values[0] != "remote" {
			continue
		}
		if len(values) < 2 || len(values) > 4 {
			return errInvalidConfiguration
		}
		port := defaultPort
		if len(values) > 2 {
			var err error
			port, err = strconv.Atoi(values[2])
			if err != nil {
				return errInvalidConfiguration
			}
		}
		remoteProtocol := protocol
		if len(values) > 3 {
			remoteProtocol = values[3]
		}
		network := "udp"
		if strings.HasPrefix(remoteProtocol, "tcp") && !strings.Contains(remoteProtocol, "server") {
			network = "tcp"
		} else if !strings.HasPrefix(remoteProtocol, "udp") {
			return errInvalidConfiguration
		}
		target, err := plan.target(values[1], port)
		if err != nil {
			return err
		}
		plan.relays = append(plan.relays, relayRequest{network, target, func(localPort int) {
			transport := "udp"
			if network == "tcp" {
				transport = "tcp-client"
			}
			lines[index] = fmt.Sprintf("remote 127.0.0.1 %d %s", localPort, transport)
			plan.configuration["config"] = strings.Join(lines, "\n")
		}})
	}
	return nil
}

func (plan *transportPlan) prepareXray() error {
	text, _ := plan.configuration["config"].(string)
	if json.Unmarshal([]byte(text), &plan.xray) != nil || plan.xray == nil {
		return errInvalidConfiguration
	}
	identifier := make([]byte, 24)
	if _, err := rand.Read(identifier); err != nil {
		return err
	}
	plan.username = hex.EncodeToString(identifier[:8])
	plan.password = hex.EncodeToString(identifier[8:])
	plan.xrayTag = "amnezia-warp-" + plan.username
	outbounds, _ := plan.xray["outbounds"].([]any)
	for _, value := range outbounds {
		outbound, _ := value.(map[string]any)
		settings, _ := outbound["settings"].(map[string]any)
		matched := false
		for _, key := range []string{"vnext", "servers"} {
			servers, _ := settings[key].([]any)
			for _, value := range servers {
				server, _ := value.(map[string]any)
				host, _ := server["address"].(string)
				port, err := configurationPort(server["port"])
				if err != nil {
					return err
				}
				if _, err := plan.target(host, port); err != nil {
					return err
				}
				matched = true
			}
		}
		if matched {
			if outbound["proxySettings"] != nil {
				return errInvalidConfiguration
			}
			stream, _ := outbound["streamSettings"].(map[string]any)
			if stream == nil {
				stream = make(map[string]any)
				outbound["streamSettings"] = stream
			}
			sockopt, _ := stream["sockopt"].(map[string]any)
			if sockopt == nil {
				sockopt = make(map[string]any)
				stream["sockopt"] = sockopt
			}
			if sockopt["dialerProxy"] != nil {
				return errInvalidConfiguration
			}
			sockopt["dialerProxy"] = plan.xrayTag
		}
	}
	return nil
}

func (plan *transportPlan) attachSocks(port int) error {
	outbounds, _ := plan.xray["outbounds"].([]any)
	outbound := map[string]any{
		"tag": plan.xrayTag, "protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"user": plan.username, "pass": plan.password}},
		}}},
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		outbound["streamSettings"] = map[string]any{"sockopt": map[string]any{"interface": "lo0"}}
	}
	plan.xray["outbounds"] = append(outbounds, outbound)
	data, err := json.Marshal(plan.xray)
	if err == nil {
		plan.configuration["config"] = string(data)
	}
	return err
}
