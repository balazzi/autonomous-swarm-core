//! Dynamic Resource Optimizer — thermodynamic governor.
//!
//! Reads physical device vectors (thermal, voltage sag, memory pressure) and
//! scales the swarm's active density *before* the host OS resorts to thermal
//! throttling or OOM kills. This is the governor every platform bridge feeds.
use crate::GLOBAL_SWARM;
use core::sync::atomic::Ordering;

/// One telemetry frame from the host platform layer.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KernelTelemetryFrame {
    pub core_temperature_celsius: f32,
    pub voltage_drop_derivative: f32, // rate of power loss
    pub anonymous_memory_pages_pct: f32,
}

pub struct ResourceGovernor;

impl ResourceGovernor {
    /// Evaluates device environment metrics and applies the swarm ceiling.
    /// Returns the active agent count now in force.
    pub fn analyze_and_scale(telemetry: &KernelTelemetryFrame) -> u8 {
        let heavy_thermal_load = telemetry.core_temperature_celsius > 42.0;
        let systemic_voltage_sag = telemetry.voltage_drop_derivative > 0.04;
        let memory_saturation = telemetry.anonymous_memory_pages_pct > 85.0;

        let dynamic_target = if heavy_thermal_load || systemic_voltage_sag {
            5 // thermal / power emergency: executives only
        } else if memory_saturation {
            8 // shed filesystem + cache scanning nodes
        } else {
            15 // nominal: full cryptographic security density
        };

        GLOBAL_SWARM.dynamic_scale_topology(dynamic_target);
        GLOBAL_SWARM.active_agent_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static GOV_LOCK: Mutex<()> = Mutex::new(());

    fn frame(t: f32, v: f32, m: f32) -> KernelTelemetryFrame {
        KernelTelemetryFrame {
            core_temperature_celsius: t,
            voltage_drop_derivative: v,
            anonymous_memory_pages_pct: m,
        }
    }

    #[test]
    fn thermal_stress_drops_to_executives() {
        let _g = GOV_LOCK.lock().unwrap();
        assert_eq!(ResourceGovernor::analyze_and_scale(&frame(46.2, 0.06, 89.5)), 5);
    }

    #[test]
    fn memory_pressure_selects_medium_density() {
        let _g = GOV_LOCK.lock().unwrap();
        assert_eq!(ResourceGovernor::analyze_and_scale(&frame(36.0, 0.01, 90.0)), 8);
    }

    #[test]
    fn nominal_conditions_unlock_full_swarm() {
        let _g = GOV_LOCK.lock().unwrap();
        assert_eq!(ResourceGovernor::analyze_and_scale(&frame(36.5, 0.01, 40.0)), 15);
    }

    #[test]
    fn boundary_values_do_not_throttle() {
        let _g = GOV_LOCK.lock().unwrap();
        // exactly at thresholds is NOT over (strict > comparisons)
        assert_eq!(ResourceGovernor::analyze_and_scale(&frame(42.0, 0.04, 85.0)), 15);
    }
}
