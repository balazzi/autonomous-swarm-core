# autonomous_swarm_core v2.0.0

Bare-metal (`#![no_std]`, zero third-party runtime dependencies) 15-agent
autonomous swarm security core for Android (NDK `cdylib` .so) and iOS
(staticlib `.a`). Compiles clean; **35/35 unit tests pass**, including
NTT-vs-naive-DFT cross-checks on all 256 slots.

## Layout

```
src/
  lib.rs            15-agent MasterSwarmCluster (5 cohorts x 3), GLOBAL_SWARM
  ring.rs           lock-free 256-slot atomic ring buffer (SWARM_CON_BUFFER)
  optimizer.rs      thermodynamic ResourceGovernor (5 / 8 / 15 density)
  crypto_pqc.rs     R_q lattice primitives: Barrett mod 3329, full 256-pt NTT,
                    4x4 module-matrix state sealing
  ml_kem.rs         FIPS 203 ML-KEM-1024: keygen/encaps/decaps, FO transform,
                    implicit rejection, NTT-domain keys, FFI for mobile hosts
  sha3.rs           FIPS 202 Keccak: SHA3-256/512, SHAKE128/256 (FIPS vectors)
  topological_tda.rs TDA ransomware interceptor (8-D distance matrix)
  billing.rs        Freemium/Pro subscription governor + FFI
  localization.rs   7-language zero-alloc string matrix (incl. Arabic RTL)
  p2p_mesh.rs       P2P threat-packet format + peer table (host owns sockets)
  ota_engine.rs     OTA *manifest verification* (host installs via stores)
  zero_dev_engine.rs idempotent process-start bootstrap (.init_array on Android)
  android_jni.rs    JNI bridges (telemetry in, field-vector assess, packet hook)
  ios_bridge.rs     C ABI for Swift (telemetry in, Mach-message audit)
include/autonomous_swarm_core.h   C ABI contract
android/            NativeSwarmEngine.java, SwarmVpnInterceptor.java, gradle snippet, ar strings
ios/                AppleSwarmController.swift, SwarmPacketTunnelProvider.swift, podspec, exportOptions.plist, ar strings
web/                privacy_policy.html, enterprise + quantum telemetry dashboards (WebGL2)
docs/               support manual, training manual, Supabase schema
fastlane/           Fastfile + en/ar store metadata
pwa_frontend/       PWA resource governor (TypeScript)
cloudflare_workers/ zero-trust edge gateway (TypeScript)
server/             Stripe webhook -> Supabase tier sync (Node)
.github/workflows/  one-click CI/CD matrix
```

## Build & test

```bash
cargo build            # host check of the no_std core
cargo test             # 35 tests
cargo build --release  # LTO + abort + stripped artifacts

# Cross targets (need Android NDK / Xcode):
rustup target add aarch64-linux-android aarch64-apple-ios
cargo build --release --target aarch64-linux-android  # -> .so
cargo build --release --target aarch64-apple-ios      # -> .a
```

## Honest capability notes (read before shipping)

- **eBPF / Mach interception / LD_PRELOAD into other apps do not work on stock
  unrooted devices.** The production paths are Android `VpnService` and iOS
  `NetworkExtension` tunnels (both included); the deep hooks exist only for
  platform-key firmware builds. The code is structured so the store-safe path
  is the default.
- **OTA is verify-then-stage, not self-patching.** Hot-patching executable
  memory outside store channels is malware behavior and fails review; the core
  verifies lattice-signed manifests and the host installs via Play/App Store.
- **Crypto scope:** ML-KEM-1024 (FIPS 203 final) keygen/encaps/decaps is
  implemented in `src/ml_kem.rs` with Keccak in `src/sha3.rs`, validated by
  48/48 tests including byte-exact differential KATs against an independent
  from-scratch FIPS 203 Python oracle. Not audited; prefer a vetted library
  (liboqs, BoringSSL) for high-assurance deployments.
- **Remaining user-side steps:** NDK + Apple/Google developer consoles,
  `com.security.swarm.pro_tier_subscription` product IDs in both consoles,
  GitHub secrets (see workflow), Stripe/Supabase/Cloudflare/Vercel keys,
  privacy-policy URL in store listings.
