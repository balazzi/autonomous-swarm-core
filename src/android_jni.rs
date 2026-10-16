//! Android NDK bridge (JNI).
//!
//! All entry points take/return primitives only — no object graphs cross
//! the JNI border, which keeps the no_std core free of allocator use and
//! eliminates the usual jbyteArray buffer-overflow surface.
//!
//! Platform reality: on unrooted commercial devices there is no eBPF
//! socket interception (that requires platform keys / custom firmware).
//! The production path is the `SwarmVpnInterceptor` VpnService in
//! android/, which feeds packet descriptors here via
//! `native_kernel_ebpf_intercept`. The function keeps its name for ABI
//! stability; on firmware builds it fronts the real eBPF program.
use crate::optimizer::{KernelTelemetryFrame, ResourceGovernor};
use crate::{AgentState, GLOBAL_SWARM, MAX_AGENTS};
use core::sync::atomic::Ordering;

pub type JniEnv = *mut core::ffi::c_void;
pub type JClass = *mut core::ffi::c_void;

/// JNI: com.security.swarm.NativeSwarmEngine.injectSystemTelemetry(float,float,float)
#[no_mangle]
pub unsafe extern "C" fn Java_com_security_swarm_NativeSwarmEngine_injectSystemTelemetry(
    _env: JniEnv,
    _class: JClass,
    temp: f32,
    voltage_sag: f32,
    mem_pressure: f32,
) -> i32 {
    let frame = KernelTelemetryFrame {
        core_temperature_celsius: temp,
        voltage_drop_derivative: voltage_sag,
        anonymous_memory_pages_pct: mem_pressure,
    };
    ResourceGovernor::analyze_and_scale(&frame) as i32
}

/// JNI: com.security.swarm.NativeSwarmEngine.assessFieldVector(int,long,long)
/// Runs one agent's lattice-variance check from Java. Returns 1 nominal, 0 quarantined.
#[no_mangle]
pub unsafe extern "C" fn Java_com_security_swarm_NativeSwarmEngine_assessFieldVector(
    _env: JniEnv,
    _class: JClass,
    agent_id: i32,
    behavior: u64,
    boundary: u64,
) -> i32 {
    let idx = (agent_id.max(0) as usize).min(MAX_AGENTS - 1);
    GLOBAL_SWARM.agent_matrix[idx].assess_execution_vector(behavior, boundary) as i32
}

/// Packet-path hook. Called per packet by the VpnService loop (unrooted) or
/// by the eBPF program (platform firmware). Returns 0 = allow, -1 = anomaly.
#[no_mangle]
pub unsafe extern "C" fn native_kernel_ebpf_intercept(packet_descriptor: i32) -> i32 {
    let network_active = GLOBAL_SWARM.agent_matrix[6].state.load(Ordering::Relaxed)
        == AgentState::ActiveMonitoring as u8;
    if !network_active {
        return 0; // cohort dormant under governor orders: bypass, no latency
    }
    if packet_descriptor < 0 {
        return -1;
    }
    0
}
