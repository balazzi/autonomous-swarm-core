package com.security.swarm;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

/**
 * Unrooted network interception path. eBPF socket hooks are unavailable on
 * stock Android (they need platform keys), so the production design is a
 * local VpnService tunnel: packets are read from the TUN fd and each
 * descriptor is offered to the Rust NetworkWarden cohort via
 * native_kernel_ebpf_intercept. When the governor has parked that cohort
 * (thermal/memory pressure), the native side bypasses instantly.
 */
public final class SwarmVpnInterceptor extends VpnService implements Runnable {

    static {
        System.loadLibrary("autonomous_swarm_core");
    }

    private static native int native_kernel_ebpf_intercept(int packetDescriptor);

    private volatile Thread tunnelThread;
    private ParcelFileDescriptor vpnInterface;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (tunnelThread == null) {
            tunnelThread = new Thread(this, "SwarmNetworkSentinel");
            tunnelThread.start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Thread t = tunnelThread;
        tunnelThread = null;
        if (t != null) {
            t.interrupt();
        }
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
            }
        } catch (Exception ignored) {
        }
        super.onDestroy();
    }

    @Override
    public void run() {
        try {
            Builder builder = new Builder()
                    .setSession("SwarmTunnel")
                    .addAddress("10.0.0.1", 24)
                    .addDnsServer("8.8.8.8")
                    .addRoute("0.0.0.0", 0);
            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                return;
            }
            int rawFd = vpnInterface.getFd();

            while (tunnelThread != null && !Thread.currentThread().isInterrupted()) {
                int status = native_kernel_ebpf_intercept(rawFd);
                if (status == -1) {
                    break; // structural anomaly: tear the tunnel down
                }
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (Exception ignored) {
            // safe termination: tunnel simply stops
        } finally {
            try {
                if (vpnInterface != null) {
                    vpnInterface.close();
                }
            } catch (Exception ignored) {
            }
        }
    }
}
