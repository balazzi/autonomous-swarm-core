# Enterprise Technical Support Manual: 15-Agent Swarm Core
**System:** Quantum-safe distributed endpoint defense platform
**Core:** `autonomous_swarm_core` v2.0.0 — `#![no_std]`, zero third-party runtime deps
**Targets:** Android (NDK cdylib .so) · iOS (staticlib .a)

---

## 1. System Topology

15 agents in 5 cohorts of 3: MemorySentinel (3–5), NetworkWarden (6–8),
FileSystemObfuscator (9–11), CryptographicSigner (12–14), ExecutiveOrchestrator (0–2).
The `ResourceGovernor` scales active density 15 → 8 → 5 on thermal / voltage /
memory pressure. Inter-agent state syncs through the lock-free 256-slot ring
buffer (`SWARM_CON_BUFFER`); ring commits are lattice-sealed via
`ModuleMatrix::encapsulate_state_vector`.

## 2. Fault Codes & Remediation

### `ORPHAN_AGENT_BYZANTINE`
- **Symptom:** agent `state == Quarantined (2)`, reputation debited 200.
- **Cause:** execution vector outside the M-LWE lattice boundary (tamper, DBI hook).
- **Auto-remediation:** surviving agents keep quorum; the quarantined agent is
  excluded from consensus until the host re-attests. To force a clean baseline:
  call `swarm_zero_dev_bootstrap()` — it is idempotent — then feed a nominal
  telemetry frame so the governor re-expands density.
- **Manual:** `adb shell am broadcast -a com.security.swarm.FORCE_TELEMETRY --ef temp 36.5 --ef mem 40.0`

### `THERMODYNAMIC_SATURATION_LOCK`
- **Symptom:** `active_agent_count` pinned at 5, TDA/file cohorts dormant.
- **Cause:** sustained temp > 42.0 °C, voltage sag > 0.04, or memory > 85%.
- **Check:** `adb shell "logcat -d | grep -i swarm"` for governor transitions.
- **Remediation:** none required — this is the governor working. If it never
  recovers, suspect a stuck sensor: reboot clears the frame cache.

### `OTA_MANIFEST_REJECTED`
- **Symptom:** `swarm_ota_verify_manifest` returns 0, `patch_staged == false`.
- **Cause:** manifest lattice signature does not fold to the release boundary
  (tampered bundle, wrong release key).
- **Remediation:** re-sign with the current release key, re-run the release
  tooling's `seal_manifest` to recompute the boundary, redistribute through
  Play/App Store channels. Never sideload to bypass this.

### `MESH_AUTH_TAG_MISMATCH`
- **Symptom:** peer threat packets fail the lattice checksum fold.
- **Cause:** mismatched core versions across the mesh (checksum folds the
  device id through `barrett_reduce`, which is version-stable — so mismatch
  means a foreign/forged sender).
- **Remediation:** drop the peer (`p2p_unregister_peer`), re-key the mesh.

## 3. Platform Recovery Paths
- **Android:** if the VpnService tunnel dies, `onDestroy` closes the fd and the
  Warden cohort bypasses (`native_kernel_ebpf_intercept` returns 0 while the
  cohort is dormant). Restart the service; no native state is lost.
- **iOS:** if the PacketTunnelProvider crashes, the system tears down the
  tunnel; the Swift controller's next `executeDynamicOptimizationCycle()` call
  re-syncs governor state. The static core holds no tunnel handles.

## 4. JNI / FFI Border Rules
- Only primitives cross the border (`f32`, `i32`, `u64`, raw pointers + len).
- `swarm_localized_disclosure` returns a `'static` pointer — hosts must NOT free.
- `p2p_encode_threat` / `swarm_ota_verify_manifest` null-check all pointers.
- Panics trap the thread (spin-loop) rather than unwinding across Java/ObjC frames.

## 5. Build & Verify
```bash
cargo build --release            # host check of the no_std core
cargo test                       # 40+ unit tests: NTT vs naive DFT, Barrett,
                                 # governor thresholds, TDA, billing, mesh, OTA
```
Cross targets (need Android NDK / Xcode):
```bash
rustup target add aarch64-linux-android aarch64-apple-ios
cargo build --release --target aarch64-linux-android   # -> .so
cargo build --release --target aarch64-apple-ios       # -> .a
```
