//! iOS Darwin bridge (C ABI for Swift/ObjC).
//!
//! Platform reality: on stock iOS there is no Mach-port interception of
//! other processes and no kernel event taps for third-party apps. The
//! production path is the `SwarmPacketTunnelProvider` NetworkExtension in
//! ios/, which streams packet flow here. `ios_mach_port_security_audit`
//! audits the *tunnel's own* Mach messages (enterprise supervised /
//! MDM-managed profiles); it is not a cross-process hook.
use crate::optimizer::{KernelTelemetryFrame, ResourceGovernor};
use crate::{AgentState, GLOBAL_SWARM};
use core::sync::atomic::Ordering;

#[repr(C)]
pub struct MachMessageHeader {
    pub msgh_bits: u32,
    pub msgh_size: u32,
    pub msgh_remote_port: u32,
    pub msgh_local_port: u32,
    pub msgh_voucher_port: u32,
    pub msgh_id: i32,
}

/// Called by AppleSwarmController with Darwin telemetry. Returns the active
/// agent count now in force.
#[no_mangle]
pub unsafe extern "C" fn ios_process_telemetry_vector(temp: f32, voltage: f32, memory: f32) -> u8 {
    let frame = KernelTelemetryFrame {
        core_temperature_celsius: temp,
        voltage_drop_derivative: voltage,
        anonymous_memory_pages_pct: memory,
    };
    ResourceGovernor::analyze_and_scale(&frame)
}

/// Audits a Mach message arriving on the tunnel's own control port.
/// Returns 0 = integrity holds, 0xDEAD = rogue IPC signature blocked,
/// -1 = null message.
#[no_mangle]
pub unsafe extern "C" fn ios_mach_port_security_audit(message_ptr: *mut core::ffi::c_void) -> i32 {
    if message_ptr.is_null() {
        return -1;
    }
    let header = &*(message_ptr as *const MachMessageHeader);
    let memory_active = GLOBAL_SWARM.agent_matrix[3].state.load(Ordering::Relaxed)
        == AgentState::ActiveMonitoring as u8;
    if !memory_active {
        return 0; // governor suspended this layer: pass through
    }
    if header.msgh_id == 0x444D5054 {
        GLOBAL_SWARM.agent_matrix[3]
            .cryptographic_reputation
            .fetch_sub(50, Ordering::SeqCst);
        return 0xDEAD;
    }
    0
}
