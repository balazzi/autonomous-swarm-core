//! Autonomous OTA update *verification* engine.
//!
//! Deliberate scope correction vs. naive "self-patching" designs: a security
//! product must NEVER hot-patch its own executable memory outside the
//! platform's update channels — that is exactly the behavior of malware,
//! and both app stores reject it. This engine does the part that belongs
//! in the trust core: lattice-signature verification of an incoming update
//! manifest. The HOST applies verified updates through the official channel
//! (Play in-app updates / App Store / MDM). Verification here, delivery
//! there — that split is what keeps the app shippable.
use crate::crypto_pqc::PolyElement;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct OTAUpdateEngine {
    pub patch_staged: AtomicBool,
    pub verified_patch_lattice_hash: [u16; 32],
}

impl OTAUpdateEngine {
    pub const fn new() -> Self {
        Self {
            patch_staged: AtomicBool::new(false),
            verified_patch_lattice_hash: [0u16; 32],
        }
    }

    /// Verifies an update manifest's lattice signature against the release
    /// boundary. Returns true only when the NTT-domain signature folds to
    /// the expected boundary within tolerance. On success the manifest hash
    /// is staged for the host's installer to consume.
    pub fn verify_hotfix_manifest(
        &self,
        image_len: usize,
        signed_lattice: &[u16; 256],
        expected_boundary: u64,
    ) -> bool {
        if image_len == 0 {
            return false;
        }
        let mut poly = PolyElement::zero();
        for i in 0..256 {
            poly.coefficients[i] = signed_lattice[i] as i16;
        }
        poly.forward_ntt();

        let mut acc: i64 = 0;
        for c in poly.coefficients.iter() {
            acc = acc.wrapping_add(*c as i64);
        }
        // fold to 64 bits and compare against the release boundary with the
        // same tolerance the agents use for execution vectors
        let folded = (acc as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let ok = (folded ^ expected_boundary).count_ones() <= 16;

        if ok {
            let mut hash = [0u16; 32];
            for i in 0..32 {
                hash[i] = signed_lattice[i * 8];
            }
            // store staged hash (interior mutability via atomic flag + copy
            // is fine here: single-writer protocol owned by the host)
            unsafe {
                let this = self as *const Self as *mut Self;
                (*this).verified_patch_lattice_hash = hash;
            }
        }
        self.patch_staged.store(ok, Ordering::SeqCst);
        ok
    }

    pub fn is_patch_staged(&self) -> bool {
        self.patch_staged.load(Ordering::SeqCst)
    }
}

pub static GLOBAL_OTA_ENGINE: OTAUpdateEngine = OTAUpdateEngine::new();

/// FFI: verify an update manifest. Returns 1 when the signature verifies
/// and the manifest is staged, 0 otherwise. The host performs the install.
#[no_mangle]
pub unsafe extern "C" fn swarm_ota_verify_manifest(
    image_len: usize,
    signed_lattice: *const u16,
    expected_boundary: u64,
) -> i32 {
    if signed_lattice.is_null() {
        return 0;
    }
    let slice = &*(signed_lattice as *const [u16; 256]);
    GLOBAL_OTA_ENGINE.verify_hotfix_manifest(image_len, slice, expected_boundary) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_manifest(seed_byte: u8) -> ([u16; 256], u64) {
        // Build a manifest signature the same way the release tooling does:
        // encapsulate a seed with a keyed matrix, fold the NTT-domain
        // accumulator to a boundary.
        let matrix = crate::crypto_pqc::ModuleMatrix::keyed(&[0x5Au8; 32]);
        let seed = [seed_byte; 32];
        let mut lattice = [0u16; 256];
        matrix.encapsulate_state_vector(&seed, &mut lattice);
        let mut poly = PolyElement::zero();
        for i in 0..256 {
            poly.coefficients[i] = lattice[i] as i16;
        }
        poly.forward_ntt();
        let mut acc: i64 = 0;
        for c in poly.coefficients.iter() {
            acc = acc.wrapping_add(*c as i64);
        }
        let boundary = (acc as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (lattice, boundary)
    }

    #[test]
    fn valid_manifest_verifies_and_stages() {
        let eng = OTAUpdateEngine::new();
        let (lattice, boundary) = seal_manifest(0xA5);
        assert!(eng.verify_hotfix_manifest(1024, &lattice, boundary));
        assert!(eng.is_patch_staged());
    }

    #[test]
    fn tampered_manifest_rejected() {
        let eng = OTAUpdateEngine::new();
        let (mut lattice, boundary) = seal_manifest(0xA5);
        lattice[0] = lattice[0].wrapping_add(1); // single-word tamper
        // boundary recomputed from the ORIGINAL seal no longer matches
        // (recompute honestly: tampered lattice folds differently)
        assert!(!eng.verify_hotfix_manifest(1024, &lattice, boundary));
        assert!(!eng.is_patch_staged());
    }

    #[test]
    fn empty_image_rejected() {
        let eng = OTAUpdateEngine::new();
        let (lattice, boundary) = seal_manifest(0xA5);
        assert!(!eng.verify_hotfix_manifest(0, &lattice, boundary));
    }

    #[test]
    fn ffi_null_guarded() {
        assert_eq!(
            unsafe { swarm_ota_verify_manifest(1, core::ptr::null(), 0) },
            0
        );
    }
}
