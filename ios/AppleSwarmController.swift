import Foundation

/**
 * Production iOS controller: marshals Darwin telemetry into the Rust core.
 *
 * Uses only public APIs available to App Store apps:
 *  - ProcessInfo.thermalState for the thermal vector (no private sysctl keys;
 *    HW_THERMAL_LEVEL does not exist on iOS and private IOKit thermal reads
 *    are rejected at review)
 *  - host_statistics64 for anonymous/wired memory pressure
 * Voltage sag is not observable on iOS: reported as 0.0.
 */
public final class AppleSwarmController {

    public static let shared = AppleSwarmController()
    private init() {}

    /// Pushes one telemetry frame into the Rust ResourceGovernor.
    /// - Returns: active agent count now in force (5 / 8 / 15).
    @discardableResult
    public func executeDynamicOptimizationCycle() -> UInt8 {
        // 1. Thermal state -> conservative Celsius estimate for the governor.
        let cpuThermalCelsius: Float
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: cpuThermalCelsius = 36.5
        case .fair:    cpuThermalCelsius = 40.0
        case .serious: cpuThermalCelsius = 43.0
        case .critical: cpuThermalCelsius = 46.0
        @unknown default: cpuThermalCelsius = 40.0
        }

        // 2. Memory pressure from Mach host statistics.
        var memoryPressurePct: Float = 40.0
        var vmStat = vm_statistics64()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &vmStat) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        if kr == KERN_SUCCESS {
            let total = Double(vmStat.free_count + vmStat.active_count
                             + vmStat.inactive_count + vmStat.wire_count)
            if total > 0 {
                memoryPressurePct = Float(
                    Double(vmStat.active_count + vmStat.wire_count) / total * 100.0)
            }
        }

        // 3. Zero-overhead hop into the static Rust core.
        return ios_process_telemetry_vector(cpuThermalCelsius, 0.0, memoryPressurePct)
    }
}
