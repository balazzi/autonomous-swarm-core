#ifndef AUTONOMOUS_SWARM_CORE_H
#define AUTONOMOUS_SWARM_CORE_H
/*
 * autonomous_swarm_core — cross-platform C ABI contract.
 * Swift/ObjC include this via the bridging header; Android links the
 * cdylib .so and resolves the JNI-mangled names below.
 */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shared telemetry frame layout (must match Rust KernelTelemetryFrame). */
typedef struct {
    float core_temperature_celsius;
    float voltage_drop_derivative;
    float anonymous_memory_pages_pct;
} KernelTelemetryFrame;

/* ---- Android JNI (resolved via System.loadLibrary, do NOT call directly) -- */
int32_t Java_com_security_swarm_NativeSwarmEngine_injectSystemTelemetry(
    void* env, void* clazz, float temp, float voltage_sag, float mem_pressure);
int32_t Java_com_security_swarm_NativeSwarmEngine_assessFieldVector(
    void* env, void* clazz, int32_t agent_id, uint64_t behavior, uint64_t boundary);

/* Packet-path hook shared by the VpnService loop / firmware eBPF program. */
int32_t native_kernel_ebpf_intercept(int32_t packet_descriptor);

/* ---- iOS Darwin bridge (callable from Swift via bridging header) --------- */
uint8_t ios_process_telemetry_vector(float temp, float voltage, float memory);
int32_t ios_mach_port_security_audit(void* message_ptr);

/* ---- P2P mesh: host owns sockets, core owns format ---------------------- */
int32_t p2p_register_peer(int32_t fd);
int32_t p2p_unregister_peer(int32_t fd);
int32_t p2p_peer_fd(uint32_t slot);
/* Encodes a lattice-tagged threat packet into `out`. Returns bytes written. */
size_t  p2p_encode_threat(const uint8_t* device_id /*[16]*/,
                          float entropy,
                          uint8_t* out, size_t out_len);

/* ---- OTA: verify-then-stage (host installs via official channels) -------- */
int32_t swarm_ota_verify_manifest(size_t image_len,
                                  const uint16_t* signed_lattice /*[256]*/,
                                  uint64_t expected_boundary);

/* ---- Billing: 0 = freemium, 1 = pro. Returns 0 ok, -1 invalid tier ------ */
int32_t swarm_set_subscription_tier(uint8_t tier);

/* ---- Localization: returns 'static UTF-8 payload (do NOT free) ----------- */
const uint8_t* swarm_localized_disclosure(uint8_t lang_code,
                                          size_t* out_len,
                                          uint8_t* out_rtl);

/* ---- Zero-dev bootstrap: idempotent process-start init ------------------ */
int32_t swarm_zero_dev_bootstrap(void);

#ifdef __cplusplus
}
#endif

#endif /* AUTONOMOUS_SWARM_CORE_H */
