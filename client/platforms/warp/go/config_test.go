package warptransport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func jsonText(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testUnderlay() underlayConfiguration {
	var config underlayConfiguration
	config.ServerHost = "vpn.example"
	config.ServerAddress = "192.0.2.2"
	config.AWG.PrivateKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	config.AWG.PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	config.AWG.Address = "192.0.2.1"
	config.AWG.Endpoint = "127.0.0.1"
	config.AWG.Port = 2408
	config.AWG.InitPacket = "<b 0x01020304>"
	return config
}

func TestWireguardPlanPreservesCredentialsAndRoutes(t *testing.T) {
	configuration := map[string]any{
		"hostName": "vpn.example", "port": 51820, "mtu": "1420",
		"client_priv_key": "test-client-key", "server_pub_key": "test-server-key",
		"psk_key": "test-psk", "allowed_ips": []string{"0.0.0.0/0", "::/0"},
		"Jc": "4", "I1": "<b 0x1122>", "splitTunnelType": 2,
	}
	original := jsonText(t, configuration)
	for _, protocol := range []string{"wireguard", "awg"} {
		t.Run(protocol, func(t *testing.T) {
			plan, err := parsePlan(jsonText(t, testUnderlay()), protocol, original)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.relays) != 1 || plan.relays[0].network != "udp" ||
				plan.relays[0].remote != netip.MustParseAddrPort("192.0.2.2:51820") {
				t.Fatal("unexpected relay")
			}
			plan.relays[0].apply(41000)
			if plan.configuration["hostName"] != "127.0.0.1" || plan.configuration["port"] != 41000 ||
				plan.configuration["mtu"] != "1280" {
				t.Fatal("endpoint was not rewritten")
			}
			for key, value := range configuration {
				if key == "hostName" || key == "port" || key == "mtu" {
					continue
				}
				if jsonText(t, plan.configuration[key]) != jsonText(t, value) {
					t.Fatalf("changed %s", key)
				}
			}
		})
	}
}

func TestSmallerMTU(t *testing.T) {
	for _, test := range []struct {
		input any
		want  string
	}{{nil, "1280"}, {"1420", "1280"}, {1280, "1280"}, {"1200", "1200"}, {"bad", "1280"}, {-1, "1280"}} {
		if got := smallerMTU(test.input); got != test.want {
			t.Fatalf("MTU: got %s, want %s", got, test.want)
		}
	}
}

func TestUnderlayRejectsMalformedInputs(t *testing.T) {
	tests := map[string]func(*underlayConfiguration){
		"private key":   func(c *underlayConfiguration) { c.AWG.PrivateKey = "invalid" },
		"public key":    func(c *underlayConfiguration) { c.AWG.PublicKey = "AQ==" },
		"ipv6 address":  func(c *underlayConfiguration) { c.AWG.Address = "2001:db8::1" },
		"ipv6 endpoint": func(c *underlayConfiguration) { c.AWG.Endpoint = "2001:db8::2" },
		"hostname":      func(c *underlayConfiguration) { c.AWG.Endpoint = "warp.example" },
		"port":          func(c *underlayConfiguration) { c.AWG.Port = 0 },
		"injection":     func(c *underlayConfiguration) { c.AWG.InitPacket = "<b 0x01\nreplace_peers=true>" },
		"odd hex":       func(c *underlayConfiguration) { c.AWG.InitPacket = "<b 0x1>" },
		"empty packet":  func(c *underlayConfiguration) { c.AWG.InitPacket = "<b 0x>" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := testUnderlay()
			mutate(&config)
			if _, err := parsePlan(jsonText(t, config), "awg", `{"hostName":"vpn.example","port":443}`); err == nil {
				t.Fatal("accepted invalid underlay")
			}
		})
	}
	for _, configuration := range []string{"null", "[]", "{", `{"hostName":"vpn.example","port":443.5}`,
		`{"hostName":"2001:db8::2","port":443}`, `{"hostName":"0.0.0.0","port":443}`,
		`{"hostName":"224.0.0.1","port":443}`} {
		if _, err := parsePlan(jsonText(t, testUnderlay()), "awg", configuration); err == nil {
			t.Fatal("accepted invalid protocol configuration")
		}
	}
	if _, err := parsePlan(jsonText(t, testUnderlay()), "ikev2", `{}`); err == nil {
		t.Fatal("accepted unsupported mobile protocol")
	}
}

func TestUnderlayOnlyAllowsVPNServerAddresses(t *testing.T) {
	config := testUnderlay()
	uapi, err := config.uapi(map[string]netip.AddrPort{
		"one": netip.MustParseAddrPort("192.0.2.2:443"), "two": netip.MustParseAddrPort("192.0.2.2:1194"),
		"three": netip.MustParseAddrPort("198.51.100.2:443"),
	}, 500)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(uapi, "allowed_ip=") != 2 || !strings.Contains(uapi, "allowed_ip=192.0.2.2/32\n") ||
		!strings.Contains(uapi, "allowed_ip=198.51.100.2/32\n") || strings.Contains(uapi, "0.0.0.0/0") ||
		!strings.Contains(uapi, "endpoint=127.0.0.1:500\n") {
		t.Fatal("unexpected underlay routes")
	}
}

func TestOpenVPNPlanPreservesTLSAndConnectionSemantics(t *testing.T) {
	text := "client\nremote 'vpn.example'\nproto tcp-client\nrport 443\nlocal 198.51.100.1\n" +
		"remote-random-hostname\n<ca>\nremote vpn.example 777 udp\n</ca>\n" +
		"<connection>\nremote 198.51.100.2\nproto udp6\nport 1194\n</connection>\n" +
		"--remote vpn.example 8443 tcp\nverify-x509-name tls.example name\n"
	plan, err := parsePlan(jsonText(t, testUnderlay()), "openvpn", jsonText(t, map[string]any{"config": text}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.relays) != 3 {
		t.Fatal("missing remotes")
	}
	want := []relayRequest{{network: "tcp", remote: netip.MustParseAddrPort("192.0.2.2:443")},
		{network: "udp", remote: netip.MustParseAddrPort("198.51.100.2:1194")},
		{network: "tcp", remote: netip.MustParseAddrPort("192.0.2.2:8443")}}
	for index, relay := range plan.relays {
		if relay.network != want[index].network || relay.remote != want[index].remote {
			t.Fatal("wrong inherited remote protocol or port")
		}
		relay.apply(41000 + index)
	}
	result := plan.configuration["config"].(string)
	for _, preserved := range []string{"<ca>\nremote vpn.example 777 udp\n</ca>", "verify-x509-name tls.example name",
		"remote 127.0.0.1 41000 tcp-client", "remote 127.0.0.1 41001 udp", "remote 127.0.0.1 41002 tcp-client"} {
		if !strings.Contains(result, preserved) {
			t.Fatal("lost config content")
		}
	}
	if strings.Contains(result, "local 198.51.100.1") || strings.Contains(result, "remote-random-hostname") {
		t.Fatal("unsafe endpoint override remains")
	}
}

func TestOpenVPNRejectsUnsafeOrMalformedConfig(t *testing.T) {
	for _, suffix := range []string{"http-proxy proxy.example 8080", "--socks-proxy proxy.example 1080", "config other.ovpn",
		"<connection>\n<connection>", "</connection>", "<key>\ninvalid", "remote \"unterminated", "remote vpn.example 0",
		"remote vpn.example 443 tcp-server", "rport -1", "proto"} {
		text := "remote vpn.example 1194 udp\n" + suffix
		if _, err := parsePlan(jsonText(t, testUnderlay()), "openvpn", jsonText(t, map[string]any{"config": text})); err == nil {
			t.Fatal("accepted unsafe or malformed config")
		}
	}
}

func TestOpenVPNFields(t *testing.T) {
	got, err := openVPNFields(`remote "vpn.example" 443 tcp ; ignored`)
	if err != nil || !reflect.DeepEqual(got, []string{"remote", "vpn.example", "443", "tcp"}) {
		t.Fatal("quoted fields or comment parsed incorrectly")
	}
}

func xrayConfiguration(t *testing.T, protocol string, port int) string {
	t.Helper()
	key := "vnext"
	if protocol == "shadowsocks" {
		key = "servers"
	}
	return jsonText(t, map[string]any{"config": jsonText(t, map[string]any{"outbounds": []any{
		map[string]any{"tag": "vpn", "protocol": protocol,
			"settings":       map[string]any{key: []any{map[string]any{"address": "vpn.example", "port": port}}},
			"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{"serverName": "vpn.example"}}},
		map[string]any{"tag": "direct", "protocol": "freedom"},
	}})})
}

func TestXrayPlanPreservesTLSNamesAndUsesAuthenticatedSOCKS(t *testing.T) {
	for _, protocol := range []string{"vless", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			plan, err := parsePlan(jsonText(t, testUnderlay()), "xray", xrayConfiguration(t, protocol, 443))
			if err != nil || plan.attachSocks(41000) != nil {
				t.Fatal("failed to prepare xray")
			}
			outbounds := plan.xray["outbounds"].([]any)
			proxy := outbounds[0].(map[string]any)
			stream := proxy["streamSettings"].(map[string]any)
			if stream["tlsSettings"].(map[string]any)["serverName"] != "vpn.example" ||
				stream["sockopt"].(map[string]any)["dialerProxy"] != plan.xrayTag || proxy["proxySettings"] != nil {
				t.Fatal("TLS name or transport proxy was lost")
			}
			if outbounds[1].(map[string]any)["proxySettings"] != nil || len(outbounds) != 3 ||
				len(plan.username) != 16 || len(plan.password) != 32 {
				t.Fatal("unexpected SOCKS configuration")
			}
			if target, found := plan.targets["vpn.example:443"]; !found || target != netip.MustParseAddrPort("192.0.2.2:443") {
				t.Fatal("VPN hostname was not pinned")
			}
			if _, found := plan.targets["198.51.100.3:443"]; found {
				t.Fatal("unrelated target was allowed")
			}
		})
	}
}

func TestXrayDialerProxyPreservesStreamAndSocketOptions(t *testing.T) {
	for _, stream := range []map[string]any{nil, {"security": "none"},
		{"sockopt": map[string]any{"tcpFastOpen": true, "tcpKeepAliveInterval": 30}}} {
		outbound := map[string]any{"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": "vpn.example", "port": 443}}}}
		if stream != nil {
			outbound["streamSettings"] = stream
		}
		configuration := map[string]any{"config": jsonText(t, map[string]any{"outbounds": []any{outbound}})}
		plan, err := parsePlan(jsonText(t, testUnderlay()), "ssxray", jsonText(t, configuration))
		if err != nil {
			t.Fatal(err)
		}
		proxy := plan.xray["outbounds"].([]any)[0].(map[string]any)
		gotStream := proxy["streamSettings"].(map[string]any)
		gotOptions := gotStream["sockopt"].(map[string]any)
		if gotOptions["dialerProxy"] != plan.xrayTag || proxy["proxySettings"] != nil {
			t.Fatal("missing current Xray transport proxy")
		}
		for key, value := range stream {
			if key == "sockopt" {
				for option, expected := range value.(map[string]any) {
					if jsonText(t, gotOptions[option]) != jsonText(t, expected) {
						t.Fatal("socket option was overwritten")
					}
				}
			} else if jsonText(t, gotStream[key]) != jsonText(t, value) {
				t.Fatal("stream setting was overwritten")
			}
		}
	}
}

func TestXrayRejectsExistingProxyChains(t *testing.T) {
	for _, property := range []string{"proxySettings", "dialerProxy"} {
		var configuration map[string]any
		json.Unmarshal([]byte(xrayConfiguration(t, "vless", 443)), &configuration)
		var xray map[string]any
		json.Unmarshal([]byte(configuration["config"].(string)), &xray)
		outbound := xray["outbounds"].([]any)[0].(map[string]any)
		if property == "proxySettings" {
			outbound[property] = map[string]any{"tag": "another-proxy"}
		} else {
			outbound["streamSettings"].(map[string]any)["sockopt"] = map[string]any{property: "another-proxy"}
		}
		configuration["config"] = jsonText(t, xray)
		if _, err := parsePlan(jsonText(t, testUnderlay()), "xray", jsonText(t, configuration)); err == nil {
			t.Fatal("accepted an ambiguous proxy chain")
		}
	}
}
