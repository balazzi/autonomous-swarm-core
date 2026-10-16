//! Zero-developer bootstrap engine.
//!
//! Honest capability note: on stock Android/iOS an app CANNOT inject itself
//! into *other* apps (no LD_PRELOAD into third-party processes — the sandbox
//! forbids it, and any attempt would be malware behavior). What this engine
//! really provides, and what enterprises actually deploy, is *frictionless
//! self-initialization*: the moment the host app's process starts, the
//! swarm boots to its baseline density with zero integration code beyond
//! linking the library.
//!
//! * Android (cdylib .so): runs automatically via `.init_array` — no Java
//!   init call required, though calling `swarm_zero_dev_bootstrap()`
//!   explicitly from `Application.onCreate` is also supported.
//! * iOS (staticlib .a): dyld has no `.init_array` for static archives, so
//!   the host calls `swarm_zero_dev_bootstrap()` once at launch
//!   (e.g. from `+load` or `application:didFinishLaunching:`).
use crate::{GLOBAL_P2P_MESH, GLOBAL_SWARM};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct ZeroDevOrchestrator {
    pub engine_initialized: AtomicBool,
}

impl ZeroDevOrchestrator {
    pub const fn new() -> Self {
        Self {
            engine_initialized: AtomicBool::new(false),
        }
    }

    /// Idempotent process-start bootstrap. Safe to call from multiple
    /// threads and from both the `.init_array` hook and explicit host calls.
    pub unsafe fn execute_autonomous_injection_bootstrap(&self) -> i32 {
        if self.engine_initialized.swap(true, Ordering::SeqCst) {
            return 0; // already attached to this process
        }
        // Baseline density: executives only, until the first telemetry frame
        // lets the ResourceGovernor expand.
        GLOBAL_SWARM.dynamic_scale_topology(5);
        // Reserve mesh slot 0 as the loopback control channel.
        let _ = GLOBAL_P2P_MESH.register_peer(101);
        1
    }
}

pub static ZERO_DEV_ENGINE: ZeroDevOrchestrator = ZeroDevOrchestrator::new();

/// Explicit entry point for hosts that prefer an explicit init call.
#[no_mangle]
pub unsafe extern "C" fn swarm_zero_dev_bootstrap() -> i32 {
    ZERO_DEV_ENGINE.execute_autonomous_injection_bootstrap()
}

/// Auto-run at shared-object load time on Android/Linux. The section name
/// `.init_array.00000` orders us before the host's own constructors.
#[cfg(target_os = "android")]
#[link_section = ".init_array.00000"]
pub static SWARM_INITIALIZER: unsafe extern "C" fn() = bootstrap_linker_interception;

#[no_mangle]
pub unsafe extern "C" fn bootstrap_linker_interception() {
    let _ = ZERO_DEV_ENGINE.execute_autonomous_injection_bootstrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_is_idempotent() {
        // NOTE: global statics are process-wide; run the logic on a local
        // orchestrator to avoid cross-test interference.
        let eng = ZeroDevOrchestrator::new();
        unsafe {
            assert_eq!(eng.execute_autonomous_injection_bootstrap(), 1);
            assert_eq!(eng.execute_autonomous_injection_bootstrap(), 0);
            assert_eq!(eng.execute_autonomous_injection_bootstrap(), 0);
        }
        assert!(eng.engine_initialized.load(Ordering::SeqCst));
    }
}
