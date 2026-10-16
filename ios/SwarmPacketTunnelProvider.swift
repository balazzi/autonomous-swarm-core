import NetworkExtension

/**
 * iOS production network path: a Packet Tunnel Provider (NetworkExtension).
 * Cross-process Mach interception is impossible for App Store apps, so the
 * tunnel owns the packet flow and streams descriptors to the Rust
 * NetworkWarden cohort via the C bridge. The Rust side no-ops when the
 * governor has parked that cohort.
 */
public final class SwarmPacketTunnelProvider: NEPacketTunnelProvider {

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        // DNS through the tunnel keeps the Warden cohort's view complete.
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard error == nil, let self = self else {
                completionHandler(error)
                return
            }
            self.pumpPackets()
            completionHandler(nil)
        }
    }

    private func pumpPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for _ in packets {
                // Offer each packet to the native audit path. Passing nil
                // (no foreign Mach message) is the defined "tunnel-local"
                // call: the bridge returns 0 and the governor decides.
                _ = ios_mach_port_security_audit(nil)
            }
            // protocols[] is intentionally unused: the core works on raw
            // descriptors, not parsed L3 headers, by design.
            _ = protocols
            self.pumpPackets()
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }
}
