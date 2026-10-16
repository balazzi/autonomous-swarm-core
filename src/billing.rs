//! Multi-platform subscription access governor.
//!
//! Feature gates are enforced natively against the verified store receipt
//! tier (set by the host app after Apple/Google receipt validation).
//! Freemium is pinned to the 5-agent baseline; Pro unlocks the full 15-agent
//! lattice + TDA matrix. The check is atomic and branch-cheap.
use core::sync::atomic::{AtomicU8, Ordering};

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MonetizationTier {
    FreemiumPermanent = 0,
    ProSubscription = 1,
}

pub struct DynamicSubscriptionGovernor {
    pub current_tier: AtomicU8,
}

impl DynamicSubscriptionGovernor {
    pub const fn new() -> Self {
        Self {
            current_tier: AtomicU8::new(MonetizationTier::FreemiumPermanent as u8),
        }
    }

    /// True when the active tier meets or exceeds the required tier.
    pub fn verify_feature_access(&self, required_tier: MonetizationTier) -> bool {
        self.current_tier.load(Ordering::Relaxed) >= required_tier as u8
    }

    /// Applies the tier's swarm-density policy immediately.
    pub fn enforce_tier_constraints(&self) {
        if self.current_tier.load(Ordering::Relaxed) == MonetizationTier::FreemiumPermanent as u8 {
            crate::GLOBAL_SWARM.dynamic_scale_topology(5);
        } else {
            crate::GLOBAL_SWARM.dynamic_scale_topology(15);
        }
    }
}

/// Called by the host after store receipt validation:
/// 0 = freemium, 1 = pro. Anything else is rejected.
#[no_mangle]
pub unsafe extern "C" fn swarm_set_subscription_tier(tier: u8) -> i32 {
    if tier > MonetizationTier::ProSubscription as u8 {
        return -1;
    }
    SUBSCRIPTION_GOVERNOR
        .current_tier
        .store(tier, Ordering::SeqCst);
    SUBSCRIPTION_GOVERNOR.enforce_tier_constraints();
    0
}

pub static SUBSCRIPTION_GOVERNOR: DynamicSubscriptionGovernor = DynamicSubscriptionGovernor::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static BILL_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn freemium_restricts_to_baseline() {
        let _g = BILL_LOCK.lock().unwrap();
        SUBSCRIPTION_GOVERNOR
            .current_tier
            .store(MonetizationTier::FreemiumPermanent as u8, Ordering::SeqCst);
        SUBSCRIPTION_GOVERNOR.enforce_tier_constraints();
        assert!(!SUBSCRIPTION_GOVERNOR.verify_feature_access(MonetizationTier::ProSubscription));
        assert!(SUBSCRIPTION_GOVERNOR.verify_feature_access(MonetizationTier::FreemiumPermanent));
        assert_eq!(
            crate::GLOBAL_SWARM.active_agent_count.load(Ordering::SeqCst),
            5
        );
    }

    #[test]
    fn pro_unlocks_full_matrix() {
        let _g = BILL_LOCK.lock().unwrap();
        SUBSCRIPTION_GOVERNOR
            .current_tier
            .store(MonetizationTier::ProSubscription as u8, Ordering::SeqCst);
        SUBSCRIPTION_GOVERNOR.enforce_tier_constraints();
        assert!(SUBSCRIPTION_GOVERNOR.verify_feature_access(MonetizationTier::ProSubscription));
        assert_eq!(
            crate::GLOBAL_SWARM.active_agent_count.load(Ordering::SeqCst),
            15
        );
        // restore freemium baseline for other suites
        SUBSCRIPTION_GOVERNOR
            .current_tier
            .store(MonetizationTier::FreemiumPermanent as u8, Ordering::SeqCst);
        SUBSCRIPTION_GOVERNOR.enforce_tier_constraints();
    }

    #[test]
    fn invalid_tier_rejected() {
        let _g = BILL_LOCK.lock().unwrap();
        unsafe {
            assert_eq!(swarm_set_subscription_tier(7), -1);
            assert_eq!(swarm_set_subscription_tier(1), 0);
        }
        SUBSCRIPTION_GOVERNOR
            .current_tier
            .store(MonetizationTier::FreemiumPermanent as u8, Ordering::SeqCst);
    }
}
