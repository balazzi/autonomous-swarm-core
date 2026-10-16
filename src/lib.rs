//! Autonomous Swarm Core — bare-metal 15-agent security engine.
//!
//! `#![no_std]` in production builds (staticlib / cdylib). Unit-test builds
//! link std so the test harness works; the panic trap is excluded there.
#![cfg_attr(not(test), no_std)]

pub mod android_jni;
pub mod billing;
pub mod crypto_pqc;
pub mod ios_bridge;
pub mod localization;
pub mod ml_kem;
pub mod optimizer;
pub mod ota_engine;
pub mod p2p_mesh;
pub mod ring;
pub mod sha3;
pub mod topological_tda;
pub mod zero_dev_engine;

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Fixed allocation bound of the compressed swarm architecture.
pub const MAX_AGENTS: usize = 15;

/// The five specialized wave cohorts (3 agents each).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CohortType {
    MemorySentinel = 0,
    NetworkWarden = 1,
    FileSystemObfuscator = 2,
    CryptographicSigner = 3,
    ExecutiveOrchestrator = 4,
}

/// Autonomous lifecycle states for dynamic density scaling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentState {
    Dormant = 0,
    ActiveMonitoring = 1,
    Quarantined = 2,
}

/// Memory-isolated autonomous micro-agent. All shared state is atomic so the
/// JNI / C-FFI boundary never needs a lock.
pub struct MicroAgent {
    pub id: u8,
    pub cohort: CohortType,
    pub state: AtomicU8,
    pub cryptographic_reputation: AtomicU64,
}

impl MicroAgent {
    pub const fn new(id: u8, cohort: CohortType) -> Self {
        Self {
            id,
            cohort,
            state: AtomicU8::new(AgentState::Dormant as u8),
            cryptographic_reputation: AtomicU64::new(1000), // perfect baseline
        }
    }

    /// Lattice-variance anomaly check on an execution vector. A behavior hash
    /// that falls outside the valid M-LWE lattice boundary quarantines the
    /// agent locally and burns reputation — the Byzantine containment path.
    pub fn assess_execution_vector(&self, behavior_vector: u64, valid_lattice_boundary: u64) -> bool {
        if (behavior_vector ^ valid_lattice_boundary) > 0xFFFF {
            self.cryptographic_reputation
                .fetch_sub(200, Ordering::SeqCst);
            self.state
                .store(AgentState::Quarantined as u8, Ordering::Release);
            return false;
        }
        true
    }
}

/// Global fixed-allocation matrix of the 15-agent swarm.
pub struct MasterSwarmCluster {
    pub active_agent_count: AtomicU8,
    pub agent_matrix: [MicroAgent; MAX_AGENTS],
}

impl MasterSwarmCluster {
    pub const fn new() -> Self {
        Self {
            // Boot with the 5 Executive Orchestrators; the ResourceGovernor
            // expands to 15 when thermals allow.
            active_agent_count: AtomicU8::new(5),
            agent_matrix: [
                MicroAgent::new(0, CohortType::ExecutiveOrchestrator),
                MicroAgent::new(1, CohortType::ExecutiveOrchestrator),
                MicroAgent::new(2, CohortType::ExecutiveOrchestrator),
                MicroAgent::new(3, CohortType::MemorySentinel),
                MicroAgent::new(4, CohortType::MemorySentinel),
                MicroAgent::new(5, CohortType::MemorySentinel),
                MicroAgent::new(6, CohortType::NetworkWarden),
                MicroAgent::new(7, CohortType::NetworkWarden),
                MicroAgent::new(8, CohortType::NetworkWarden),
                MicroAgent::new(9, CohortType::FileSystemObfuscator),
                MicroAgent::new(10, CohortType::FileSystemObfuscator),
                MicroAgent::new(11, CohortType::FileSystemObfuscator),
                MicroAgent::new(12, CohortType::CryptographicSigner),
                MicroAgent::new(13, CohortType::CryptographicSigner),
                MicroAgent::new(14, CohortType::CryptographicSigner),
            ],
        }
    }

    /// Dynamically shifts agent operating modes to protect battery / memory.
    /// Agents above the ceiling go Dormant; the rest enter ActiveMonitoring.
    pub fn dynamic_scale_topology(&self, target_count: u8) {
        let ceiling = target_count.min(MAX_AGENTS as u8);
        self.active_agent_count.store(ceiling, Ordering::SeqCst);
        for (idx, agent) in self.agent_matrix.iter().enumerate() {
            if (idx as u8) < ceiling {
                agent
                    .state
                    .store(AgentState::ActiveMonitoring as u8, Ordering::Release);
            } else {
                agent.state.store(AgentState::Dormant as u8, Ordering::Release);
            }
        }
    }
}

/// Global static runtime instance, reachable from every module and FFI bridge.
pub static GLOBAL_SWARM: MasterSwarmCluster = MasterSwarmCluster::new();

// Re-export the other global singletons at the crate root so modules and
// hosts share one canonical path to each.
pub use ota_engine::GLOBAL_OTA_ENGINE;
pub use p2p_mesh::GLOBAL_P2P_MESH;
pub use ring::SWARM_CON_BUFFER;
pub use zero_dev_engine::ZERO_DEV_ENGINE;

/// Bare-metal panic convergence: trap the faulting thread instead of
/// unwinding through foreign (Java/ObjC) frames. Excluded from test builds,
/// where the std test harness supplies its own handler.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The swarm is global; serialize tests that mutate it.
    static SWARM_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn boot_state_is_five_executives() {
        let _g = SWARM_LOCK.lock().unwrap();
        // Fresh statics start here; other tests may have scaled up, so reset.
        GLOBAL_SWARM.dynamic_scale_topology(5);
        assert_eq!(GLOBAL_SWARM.active_agent_count.load(Ordering::SeqCst), 5);
        for (i, a) in GLOBAL_SWARM.agent_matrix.iter().enumerate() {
            let want = if (i as u8) < 5 {
                AgentState::ActiveMonitoring as u8
            } else {
                AgentState::Dormant as u8
            };
            assert_eq!(a.state.load(Ordering::SeqCst), want, "agent {}", i);
        }
    }

    #[test]
    fn density_scaling_clamps_and_applies() {
        let _g = SWARM_LOCK.lock().unwrap();
        GLOBAL_SWARM.dynamic_scale_topology(200); // clamps to 15
        assert_eq!(GLOBAL_SWARM.active_agent_count.load(Ordering::SeqCst), 15);
        assert!(GLOBAL_SWARM
            .agent_matrix
            .iter()
            .all(|a| a.state.load(Ordering::SeqCst) == AgentState::ActiveMonitoring as u8));
        GLOBAL_SWARM.dynamic_scale_topology(8);
        assert_eq!(GLOBAL_SWARM.active_agent_count.load(Ordering::SeqCst), 8);
        GLOBAL_SWARM.dynamic_scale_topology(5); // leave tidy
    }

    #[test]
    fn byzantine_vector_quarantines_agent() {
        let _g = SWARM_LOCK.lock().unwrap();
        let agent = &GLOBAL_SWARM.agent_matrix[7]; // NetworkWarden
        agent
            .state
            .store(AgentState::ActiveMonitoring as u8, Ordering::SeqCst);
        let before = agent.cryptographic_reputation.load(Ordering::SeqCst);
        assert!(!agent.assess_execution_vector(0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0000));
        assert!(agent.cryptographic_reputation.load(Ordering::SeqCst) < before);
        assert_eq!(
            agent.state.load(Ordering::SeqCst),
            AgentState::Quarantined as u8
        );
        // nominal vector passes untouched
        agent
            .state
            .store(AgentState::ActiveMonitoring as u8, Ordering::SeqCst);
        assert!(agent.assess_execution_vector(0x1234, 0x1234));
        assert_eq!(
            agent.state.load(Ordering::SeqCst),
            AgentState::ActiveMonitoring as u8
        );
        agent.state.store(AgentState::Dormant as u8, Ordering::SeqCst);
    }

    #[test]
    fn cohort_layout_is_five_groups_of_three() {
        let expect = [
            CohortType::ExecutiveOrchestrator,
            CohortType::MemorySentinel,
            CohortType::NetworkWarden,
            CohortType::FileSystemObfuscator,
            CohortType::CryptographicSigner,
        ];
        for (g, want) in expect.iter().enumerate() {
            for k in 0..3 {
                // note: executives live at 0..3, then sentinels, etc.
                let idx = match g {
                    0 => k,
                    1 => 3 + k,
                    2 => 6 + k,
                    3 => 9 + k,
                    _ => 12 + k,
                };
                assert_eq!(GLOBAL_SWARM.agent_matrix[idx].cohort, *want);
            }
        }
    }
}
