import Foundation
import Network
import NetworkExtension

extension Constants {
    static let warpUnderlayConfigKey = "warpUnderlay"
}

extension PacketTunnelProvider {
    func protocolConfigurationData(for key: String) -> Data? {
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let configuration = tunnelProtocol.providerConfiguration else { return nil }
        if configuration[Constants.warpUnderlayConfigKey] != nil {
            return warpProtocolConfiguration
        }
        return configuration[key] as? Data
    }

    func physicalInterfaceIndex(for path: Network.NWPath) -> UInt32 {
        guard path.status == .satisfied else { return 0 }
        let preferredTypes: [NWInterface.InterfaceType] = [.wiredEthernet, .wifi, .cellular]
        for type in preferredTypes where path.usesInterfaceType(type) {
            if let interface = path.availableInterfaces.first(where: { $0.type == type }) {
                return UInt32(interface.index)
            }
        }
        return 0
    }

    func prepareWarpTransport(completion: @escaping (Error?) -> Void) {
        warpProtocolConfiguration = nil
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let configuration = tunnelProtocol.providerConfiguration,
              configuration[Constants.warpUnderlayConfigKey] != nil else {
            completion(nil)
            return
        }
        guard let underlay = configuration[Constants.warpUnderlayConfigKey] as? Data,
              let protoType else {
            completion(WarpTransportError.invalidConfiguration)
            return
        }
        let key: String
        let protocolName: String
        switch protoType {
        case .wireguard:
            key = Constants.wireGuardConfigKey
            protocolName = "awg"
        case .openvpn:
            key = Constants.ovpnConfigKey
            protocolName = "openvpn"
        case .xray:
            key = Constants.xrayConfigKey
            protocolName = "xray"
        }
        guard let protocolData = configuration[key] as? Data else {
            completion(WarpTransportError.invalidConfiguration)
            return
        }
        let transport = WarpTransport(interfaceIndex: physicalInterfaceIndex(for: pathMonitor.currentPath))
        warpTransport = transport
        transport.start(underlay: underlay, protocolName: protocolName, configuration: protocolData,
                        readinessHandler: { [weak self, weak transport] ready in
                            guard let self, self.warpTransport === transport else { return }
                            self.reasserting = !ready
                        }, failureHandler: { [weak self, weak transport] error in
                            guard let self, self.warpTransport === transport else { return }
                            self.cancelTunnelWithError(error)
                        }, completion: { [weak self, weak transport] result in
                            guard let self, self.warpTransport === transport else {
                                completion(WarpTransportError.cancelled)
                                return
                            }
                            switch result {
                            case .success(let data):
                                self.warpProtocolConfiguration = data
                                completion(nil)
                            case .failure(let error):
                                self.warpTransport = nil
                                completion(error)
                            }
                        })
    }
}
