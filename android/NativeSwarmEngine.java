package com.security.swarm;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.HardwarePropertiesManager;

/**
 * Android production controller: marshals HardwarePropertiesManager /
 * BatteryManager telemetry down into the bare-metal Rust governor.
 *
 * NOTE (bug fix vs. earlier drafts): the Java native method must be declared
 * with its SHORT name (injectSystemTelemetry). The JNI runtime resolves it
 * to the mangled Rust symbol automatically. Declaring the mangled name as
 * the Java method name does not link.
 */
public final class NativeSwarmEngine {

    static {
        System.loadLibrary("autonomous_swarm_core");
    }

    // Short names — JNI maps these to the Java_com_security_swarm_... symbols.
    private static native int injectSystemTelemetry(float cpuTemp, float voltageSag, float memoryPressure);
    private static native int assessFieldVector(int agentId, long behavior, long boundary);

    private NativeSwarmEngine() {}

    /**
     * Polls physical subsystem state and pushes it into the Rust optimizer.
     * @return active agent count now in force (5 / 8 / 15)
     */
    public static int synchroniseSubsystemMetrics(Context context) {
        float cpuTemperature = 35.0f;
        float voltageDrop = 0.0f;
        float memoryPressure = 50.0f;

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                HardwarePropertiesManager hw =
                        (HardwarePropertiesManager) context.getSystemService(Context.HARDWARE_PROPERTIES_SERVICE);
                if (hw != null) {
                    float[] temps = hw.getDeviceTemperatures(
                            HardwarePropertiesManager.DEVICE_TEMPERATURE_CPU,
                            HardwarePropertiesManager.TEMPERATURE_CURRENT);
                    if (temps != null && temps.length > 0) {
                        cpuTemperature = temps[0];
                    }
                }
            }

            IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, filter);
            if (batteryStatus != null) {
                int voltageMv = batteryStatus.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0);
                voltageDrop = voltageMv > 0 ? (4200.0f - (float) voltageMv) / 1000.0f : 0.0f;
            }

            Runtime runtime = Runtime.getRuntime();
            long maxMemory = runtime.maxMemory();
            long allocated = runtime.totalMemory() - runtime.freeMemory();
            memoryPressure = maxMemory > 0 ? ((float) allocated / maxMemory) * 100.0f : 50.0f;
        } catch (Exception ignored) {
            // passive fallback: defaults above keep the governor safe
        }

        return injectSystemTelemetry(cpuTemperature, voltageDrop, memoryPressure);
    }

    /** Runs one agent's lattice-variance check. Returns 1 nominal, 0 quarantined. */
    public static boolean assessAgentVector(int agentId, long behavior, long boundary) {
        return assessFieldVector(agentId, behavior, boundary) == 1;
    }
}
