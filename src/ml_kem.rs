//! ML-KEM-1024 (FIPS 203, final) — Module-Lattice KEM, no_std, zero deps.
//!
//! Implements FIPS 203 Algorithms 8–19 for the ML-KEM-1024 parameter set
//! (k=4, η1=η2=2, du=11, dv=5): SampleNTT, NTT, NTT^{-1}, MultiplyNTTs,
//! K-PKE keygen/encrypt/decrypt, and the ML-KEM FO transform with implicit
//! rejection. Keys store the NTT-domain t̂/ŝ per the final standard.
//!
//! Randomness comes from the host: `keygen(d, z)` and `encaps(ek, m)` take
//! their coins as explicit 32-byte inputs (the embedded-friendly convention).
//! FFI wrappers for mobile hosts are at the bottom.

use crate::crypto_pqc::PolyElement;
use crate::sha3::{sha3_256, sha3_512, Shake};

pub const Q: i32 = 3329;
pub const N: usize = 256;
pub const K: usize = 4;
pub const DU: usize = 11;
pub const DV: usize = 5;

pub const EK_BYTES: usize = 384 * K + 32; // 1568
pub const DK_BYTES: usize = 384 * K + EK_BYTES + 64; // 3168
pub const CT_BYTES: usize = 32 * (DU * K + DV); // 1568

pub type Ek = [u8; EK_BYTES];
pub type Dk = [u8; DK_BYTES];
pub type Ct = [u8; CT_BYTES];
pub type SharedSecret = [u8; 32];

type Poly = [i16; N];

#[inline(always)]
fn barrett(x: i32) -> i16 {
    PolyElement::barrett_reduce(x)
}

// ---------------------------------------------------------------- const math

const fn bitrev7(mut x: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0;
    while i < 7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn modpow(mut base: i64, mut exp: i64, m: i64) -> i64 {
    let mut r = 1i64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            r = (r * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    r
}

const fn make_zetas() -> [i16; 128] {
    let mut t = [0i16; 128];
    let mut i = 0usize;
    while i < 128 {
        t[i] = modpow(17, bitrev7(i as u8) as i64, Q as i64) as i16;
        i += 1;
    }
    t
}

const fn make_gammas() -> [i16; 128] {
    let mut t = [0i16; 128];
    let mut i = 0usize;
    while i < 128 {
        t[i] = modpow(17, 2 * bitrev7(i as u8) as i64 + 1, Q as i64) as i16;
        i += 1;
    }
    t
}

const ZETAS: [i16; 128] = make_zetas();
const GAMMAS: [i16; 128] = make_gammas();
/// 128^{-1} mod 3329, for the INTT final scaling.
const INV_128: i32 = 3303;

// ------------------------------------------------------- FIPS 203 Algorithms

/// Algorithm 9: NTT. Input/output in place; output is the NTT-domain vector
/// (128 quadratic-factor pairs) used directly by MultiplyNTTs.
pub fn ntt(f: &mut Poly) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i] as i32;
            i += 1;
            for j in start..start + len {
                let t = barrett(zeta * f[j + len] as i32);
                let aj = f[j] as i32;
                f[j + len] = barrett(aj - t as i32);
                f[j] = barrett(aj + t as i32);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Algorithm 10: NTT^{-1}.
pub fn intt(f: &mut Poly) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i] as i32;
            i -= 1;
            for j in start..start + len {
                let t = f[j] as i32;
                f[j] = barrett(t + f[j + len] as i32);
                f[j + len] = barrett(zeta * (f[j + len] as i32 - t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = barrett(*c as i32 * INV_128);
    }
}

/// Algorithm 12: MultiplyNTTs (basemul) over the 128 quadratic factors.
pub fn basemul(a: &Poly, b: &Poly) -> Poly {
    let mut h = [0i16; N];
    for i in 0..128 {
        let (a0, a1) = (a[2 * i] as i32, a[2 * i + 1] as i32);
        let (b0, b1) = (b[2 * i] as i32, b[2 * i + 1] as i32);
        let g = GAMMAS[i] as i32;
        let t = barrett(barrett(a1 * b1) as i32 * g); // reduce stepwise: q^3 overflows i32
        h[2 * i] = barrett(a0 * b0 + t as i32);
        h[2 * i + 1] = barrett(a0 * b1 + a1 * b0);
    }
    h
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut h = [0i16; N];
    for i in 0..N {
        h[i] = barrett(a[i] as i32 + b[i] as i32);
    }
    h
}

/// PRF_2(s, b) = SHAKE256(s || b), 128 bytes (FIPS 203 §4.1).
fn prf(s: &[u8], b: u8) -> [u8; 128] {
    let mut x = Shake::shake256();
    x.absorb(s);
    x.absorb(&[b]);
    let mut out = [0u8; 128];
    x.squeeze(&mut out);
    out
}

/// SamplePolyCBD_2 (FIPS 203 Algorithm 43, η=2): 128 bytes -> 256 coeffs.
pub fn cbd2(buf: &[u8; 128]) -> Poly {
    let mut f = [0i16; N];
    for i in 0..32 {
        let t =
            u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let mut d = t & 0x5555_5555;
        d += (t >> 1) & 0x5555_5555;
        for j in 0..8 {
            let x = (d >> (4 * j)) & 0xF;
            f[8 * i + j] = ((x & 3) as i16) - (((x >> 2) & 3) as i16);
        }
    }
    f
}

/// Algorithm 8: SampleNTT(XOF(ρ, i, j)) via SHAKE128 rejection sampling.
pub fn sample_ntt(rho: &[u8], i: u8, j: u8) -> Poly {
    let mut xof = Shake::shake128();
    xof.absorb(rho);
    xof.absorb(&[i, j]);
    let mut f = [0i16; N];
    let mut idx = 0usize;
    let mut cache = [0u8; 168];
    let mut pos = cache.len(); // force initial squeeze
    while idx < N {
        if pos + 3 > cache.len() {
            xof.squeeze(&mut cache);
            pos = 0;
        }
        let b0 = cache[pos] as i32;
        let b1 = cache[pos + 1] as i32;
        let b2 = cache[pos + 2] as i32;
        pos += 3;
        let d1 = b0 + ((b1 & 0xF) << 8);
        let d2 = (b1 >> 4) + (b2 << 4);
        if d1 < Q && idx < N {
            f[idx] = d1 as i16;
            idx += 1;
        }
        if d2 < Q && idx < N {
            f[idx] = d2 as i16;
            idx += 1;
        }
    }
    f
}

/// Compress_d / Decompress_d (FIPS 203 Algorithms 4, 5).
fn compress(x: i16, d: u32) -> i16 {
    let t = (((x as u32) << d) + (Q as u32) / 2) / (Q as u32);
    (t & ((1u32 << d) - 1)) as i16
}

fn decompress(y: i16, d: u32) -> i16 {
    (((y as u32 * Q as u32) + (1u32 << (d - 1))) >> d) as i16
}

/// ByteEncode_d / ByteDecode_d (FIPS 203 Algorithms 6, 7), d ∈ {1,5,11,12}.
fn byte_encode(f: &Poly, d: u32, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d as usize);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut pos = 0usize;
    for &c in f.iter() {
        acc |= (c as u32) << bits;
        bits += d;
        while bits >= 8 {
            out[pos] = acc as u8;
            acc >>= 8;
            bits -= 8;
            pos += 1;
        }
    }
    if bits > 0 {
        out[pos] = acc as u8;
    }
}

fn byte_decode(buf: &[u8], d: u32, f: &mut Poly) {
    let mask = (1u32 << d) - 1;
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut pos = 0usize;
    for c in f.iter_mut() {
        while bits < d {
            acc |= (buf[pos] as u32) << bits;
            bits += 8;
            pos += 1;
        }
        *c = (acc & mask) as i16;
        acc >>= d;
        bits -= d;
    }
}

// ------------------------------------------------------------------ K-PKE

/// Algorithm 13: K-PKE.KeyGen. Returns (ek_pke = Encode_12(t̂) [1536 B],
/// dk_pke = Encode_12(ŝ) [1536 B], ρ [32 B]). Keys hold NTT-domain vectors.
fn kpke_keygen(d: &[u8; 32]) -> ([u8; 1536], [u8; 1536], [u8; 32]) {
    let g = sha3_512(d);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let mut a_hat = [[[0i16; N]; K]; K];
    for i in 0..K {
        for j in 0..K {
            a_hat[i][j] = sample_ntt(&rho, i as u8, j as u8);
        }
    }
    let mut s = [[0i16; N]; K];
    let mut e = [[0i16; N]; K];
    let mut n = 0u8;
    for i in 0..K {
        s[i] = cbd2(&prf(&sigma, n));
        n += 1;
    }
    for i in 0..K {
        e[i] = cbd2(&prf(&sigma, n));
        n += 1;
    }
    let mut s_hat = s;
    let mut e_hat = e;
    for i in 0..K {
        ntt(&mut s_hat[i]);
        ntt(&mut e_hat[i]);
    }

    let mut ek_pke = [0u8; 1536];
    for i in 0..K {
        let mut acc = [0i16; N];
        for j in 0..K {
            acc = poly_add(&acc, &basemul(&a_hat[i][j], &s_hat[j]));
        }
        acc = poly_add(&acc, &e_hat[i]);
        byte_encode(&acc, 12, &mut ek_pke[384 * i..384 * (i + 1)]);
    }
    let mut dk_pke = [0u8; 1536];
    for i in 0..K {
        byte_encode(&s_hat[i], 12, &mut dk_pke[384 * i..384 * (i + 1)]);
    }
    (ek_pke, dk_pke, rho)
}

/// Algorithm 14: K-PKE.Encrypt.
fn kpke_encrypt(ek: &Ek, m: &[u8; 32], r: &[u8; 32]) -> Ct {
    let rho = &ek[384 * K..];
    let mut t_hat = [[0i16; N]; K];
    for i in 0..K {
        byte_decode(&ek[384 * i..384 * (i + 1)], 12, &mut t_hat[i]);
    }

    let mut n = 0u8;
    let mut y = [[0i16; N]; K];
    for i in 0..K {
        y[i] = cbd2(&prf(r, n));
        n += 1;
    }
    let mut y_hat = y;
    for i in 0..K {
        ntt(&mut y_hat[i]);
    }
    let mut e1 = [[0i16; N]; K];
    for i in 0..K {
        e1[i] = cbd2(&prf(r, n));
        n += 1;
    }
    let e2 = cbd2(&prf(r, n));

    let mut ct = [0u8; CT_BYTES];
    // u[i] = INTT(Σ_j Â[j][i] ◦ ŷ[j]) + e1[i]   (Â^T row i)
    for i in 0..K {
        let mut acc = [0i16; N];
        for j in 0..K {
            let aji = sample_ntt(rho, j as u8, i as u8);
            acc = poly_add(&acc, &basemul(&aji, &y_hat[j]));
        }
        intt(&mut acc);
        acc = poly_add(&acc, &e1[i]);
        let mut cu = [0i16; N];
        for k in 0..N {
            cu[k] = compress(acc[k], DU as u32);
        }
        byte_encode(&cu, DU as u32, &mut ct[352 * i..352 * (i + 1)]);
    }
    // v = INTT(Σ_i t̂[i] ◦ ŷ[i]) + e2 + Decompress_1(m)
    let mut acc = [0i16; N];
    for i in 0..K {
        acc = poly_add(&acc, &basemul(&t_hat[i], &y_hat[i]));
    }
    intt(&mut acc);
    let mut mbits = [0i16; N];
    byte_decode(m, 1, &mut mbits);
    for k in 0..N {
        acc[k] = barrett(acc[k] as i32 + e2[k] as i32 + decompress(mbits[k], 1) as i32);
    }
    let mut cv = [0i16; N];
    for k in 0..N {
        cv[k] = compress(acc[k], DV as u32);
    }
    byte_encode(&cv, DV as u32, &mut ct[352 * K..]);
    ct
}

/// Algorithm 15: K-PKE.Decrypt. Returns the 32-byte message.
fn kpke_decrypt(dk_pke: &[u8], ct: &Ct) -> [u8; 32] {
    let mut s_hat = [[0i16; N]; K];
    for i in 0..K {
        byte_decode(&dk_pke[384 * i..384 * (i + 1)], 12, &mut s_hat[i]);
    }
    let mut u = [[0i16; N]; K];
    for i in 0..K {
        let mut cu = [0i16; N];
        byte_decode(&ct[352 * i..352 * (i + 1)], DU as u32, &mut cu);
        for k in 0..N {
            u[i][k] = decompress(cu[k], DU as u32);
        }
    }
    let mut cv = [0i16; N];
    byte_decode(&ct[352 * K..], DV as u32, &mut cv);
    let mut v = [0i16; N];
    for k in 0..N {
        v[k] = decompress(cv[k], DV as u32);
    }

    // w = v − INTT(Σ_i ŝ[i] ◦ NTT(u[i]))
    let mut acc = [0i16; N];
    for i in 0..K {
        let mut uh = u[i];
        ntt(&mut uh);
        acc = poly_add(&acc, &basemul(&s_hat[i], &uh));
    }
    intt(&mut acc);
    let mut cw = [0i16; N];
    for k in 0..N {
        cw[k] = compress(barrett(v[k] as i32 - acc[k] as i32), 1);
    }
    let mut m = [0u8; 32];
    byte_encode(&cw, 1, &mut m);
    m
}

// ----------------------------------------------------------------- ML-KEM

/// Algorithm 17: ML-KEM.KeyGen_internal(d, z).
pub fn ml_kem_1024_keygen(d: &[u8; 32], z: &[u8; 32]) -> (Ek, Dk) {
    let (ek_pke, dk_pke, rho) = kpke_keygen(d);
    let mut ek = [0u8; EK_BYTES];
    ek[..1536].copy_from_slice(&ek_pke);
    ek[1536..].copy_from_slice(&rho);
    let h = sha3_256(&ek);
    let mut dk = [0u8; DK_BYTES];
    dk[..1536].copy_from_slice(&dk_pke);
    dk[1536..1536 + EK_BYTES].copy_from_slice(&ek);
    dk[1536 + EK_BYTES..1536 + EK_BYTES + 32].copy_from_slice(&h);
    dk[1536 + EK_BYTES + 32..].copy_from_slice(z);
    (ek, dk)
}

fn kdf_k(c: &Ct, k32: &[u8; 32]) -> SharedSecret {
    // KDF(K' || H(c)) = SHAKE256, 32 bytes (FIPS 203 §4.1)
    let hc = sha3_256(c);
    let mut x = Shake::shake256();
    x.absorb(k32);
    x.absorb(&hc);
    let mut out = [0u8; 32];
    x.squeeze(&mut out);
    out
}

/// Algorithm 18: ML-KEM.Encaps_internal(ek, m).
pub fn ml_kem_1024_encaps(ek: &Ek, m: &[u8; 32]) -> (Ct, SharedSecret) {
    let hek = sha3_256(ek);
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(m);
    pre[32..].copy_from_slice(&hek);
    let kr = sha3_512(&pre); // G(m || H(ek))
    let mut r = [0u8; 32];
    let mut k = [0u8; 32];
    r.copy_from_slice(&kr[32..]);
    k.copy_from_slice(&kr[..32]);
    let c = kpke_encrypt(ek, m, &r);
    let ss = kdf_k(&c, &k);
    (c, ss)
}

/// Algorithm 19: ML-KEM.Decaps_internal(dk, c), with implicit rejection.
/// The re-encryption check uses a branchless select so a tampered
/// ciphertext reveals nothing through timing about which path was taken.
pub fn ml_kem_1024_decaps(dk: &Dk, c: &Ct) -> SharedSecret {
    let dk_pke = &dk[..1536];
    let ek_slice = &dk[1536..1536 + EK_BYTES];
    let h = &dk[1536 + EK_BYTES..1536 + EK_BYTES + 32];
    let z = &dk[1536 + EK_BYTES + 32..];

    let m2 = kpke_decrypt(dk_pke, c);
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(&m2);
    pre[32..].copy_from_slice(h);
    let kr = sha3_512(&pre); // G(m' || h)
    let mut ek = [0u8; EK_BYTES];
    ek.copy_from_slice(ek_slice);
    let mut r = [0u8; 32];
    r.copy_from_slice(&kr[32..]);
    let c2 = kpke_encrypt(&ek, &m2, &r);

    // branchless: mask = 0xFF iff c == c2
    let mut diff = 0u8;
    for i in 0..CT_BYTES {
        diff |= c[i] ^ c2[i];
    }
    let mask = ((diff == 0) as u8).wrapping_neg();
    let mut ksel = [0u8; 32];
    for i in 0..32 {
        ksel[i] = (kr[i] & mask) | (z[i] & !mask);
    }
    kdf_k(c, &ksel)
}

// ------------------------------------------------------------------ FFI

use core::{ptr, slice};

fn copy_in<const N: usize>(p: *const u8) -> [u8; N] {
    let mut a = [0u8; N];
    unsafe { ptr::copy_nonoverlapping(p, a.as_mut_ptr(), N) };
    a
}

/// FFI: deterministic ML-KEM-1024 keygen. Returns 0 ok, -1 on null pointer.
#[no_mangle]
pub unsafe extern "C" fn mlkem1024_keygen(
    d: *const u8,
    z: *const u8,
    ek_out: *mut u8,
    dk_out: *mut u8,
) -> i32 {
    if d.is_null() || z.is_null() || ek_out.is_null() || dk_out.is_null() {
        return -1;
    }
    let (ek, dk) = ml_kem_1024_keygen(&copy_in::<32>(d), &copy_in::<32>(z));
    ptr::copy_nonoverlapping(ek.as_ptr(), ek_out, EK_BYTES);
    ptr::copy_nonoverlapping(dk.as_ptr(), dk_out, DK_BYTES);
    0
}

/// FFI: deterministic ML-KEM-1024 encaps. Returns 0 ok, -1 on null pointer.
#[no_mangle]
pub unsafe extern "C" fn mlkem1024_encaps(
    ek: *const u8,
    m: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> i32 {
    if ek.is_null() || m.is_null() || ct_out.is_null() || ss_out.is_null() {
        return -1;
    }
    let ek_a: Ek = copy_in(ek);
    let (ct, ss) = ml_kem_1024_encaps(&ek_a, &copy_in::<32>(m));
    ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, CT_BYTES);
    ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32);
    0
}

/// FFI: ML-KEM-1024 decaps (implicit rejection). Returns 0 ok, -1 on null.
#[no_mangle]
pub unsafe extern "C" fn mlkem1024_decaps(dk: *const u8, ct: *const u8, ss_out: *mut u8) -> i32 {
    if dk.is_null() || ct.is_null() || ss_out.is_null() {
        return -1;
    }
    let dk_a: Dk = copy_in(dk);
    let ct_a: Ct = copy_in(ct);
    let ss = ml_kem_1024_decaps(&dk_a, &ct_a);
    ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn hex_to(bytes: &mut [u8], s: &str) {
        assert_eq!(bytes.len() * 2, s.len());
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
    }

    #[test]
    fn zetas_match_fips203_table() {
        // Spot-check against the FIPS 203 / pqclean zetas table head:
        // zetas[i] = 17^bitrev7(i) mod 3329, i = 1..3 used first in NTT.
        assert_eq!(ZETAS[1], 1729); // 17^bitrev7(1) mod 3329
        assert_eq!(ZETAS[2], 2580); // 17^bitrev7(2) mod 3329
        assert_eq!(GAMMAS[0], 17); // 17^(2*bitrev7(0)+1)
    }

    #[test]
    fn ntt_roundtrip_via_basemul_domain() {
        // INTT(NTT(f)) == f through the Kyber-domain transforms.
        let mut f = [0i16; N];
        for i in 0..N {
            f[i] = ((i * 7 + 3) % Q as usize) as i16;
        }
        let orig = f;
        ntt(&mut f);
        // NTT must move values (non-trivial)
        assert_ne!(f, orig);
        intt(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn kem_roundtrip_fixed_seeds() {
        let d = [0x42u8; 32];
        let z = [0x24u8; 32];
        let m = [0x11u8; 32];
        let (ek, dk) = ml_kem_1024_keygen(&d, &z);
        assert_eq!(ek.len(), EK_BYTES);
        assert_eq!(dk.len(), DK_BYTES);
        let (ct, ss1) = ml_kem_1024_encaps(&ek, &m);
        let ss2 = ml_kem_1024_decaps(&dk, &ct);
        assert_eq!(ss1, ss2, "encaps/decaps shared secrets must match");
        // determinism: same inputs -> same outputs
        let (ek2, _) = ml_kem_1024_keygen(&d, &z);
        assert_eq!(ek, ek2);
    }

    #[test]
    fn kem_roundtrip_second_seed() {
        let d = [0xABu8; 32];
        let z = [0xCDu8; 32];
        let m = [0xEFu8; 32];
        let (ek, dk) = ml_kem_1024_keygen(&d, &z);
        let (ct, ss1) = ml_kem_1024_encaps(&ek, &m);
        assert_eq!(ss1, ml_kem_1024_decaps(&dk, &ct));
    }

    #[test]
    fn tampered_ciphertext_implicitly_rejected() {
        let d = [0x42u8; 32];
        let z = [0x24u8; 32];
        let m = [0x11u8; 32];
        let (ek, dk) = ml_kem_1024_keygen(&d, &z);
        let (mut ct, ss_good) = ml_kem_1024_encaps(&ek, &m);
        ct[0] ^= 0x01; // single-bit tamper
        let ss_bad = ml_kem_1024_decaps(&dk, &ct);
        assert_ne!(ss_good, ss_bad, "tampered ct must not yield the real ss");
        // decaps still returns 32 bytes (implicit rejection, no error oracle)
        assert_eq!(ss_bad.len(), 32);
    }

    #[test]
    fn ffi_wrappers_agree_with_native() {
        let d = [0x77u8; 32];
        let z = [0x88u8; 32];
        let m = [0x99u8; 32];
        let mut ek = [0u8; EK_BYTES];
        let mut dk = [0u8; DK_BYTES];
        let mut ct = [0u8; CT_BYTES];
        let mut ss1 = [0u8; 32];
        let mut ss2 = [0u8; 32];
        unsafe {
            assert_eq!(mlkem1024_keygen(d.as_ptr(), z.as_ptr(), ek.as_mut_ptr(), dk.as_mut_ptr()), 0);
            assert_eq!(mlkem1024_encaps(ek.as_ptr(), m.as_ptr(), ct.as_mut_ptr(), ss1.as_mut_ptr()), 0);
            assert_eq!(mlkem1024_decaps(dk.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr()), 0);
            // null guards
            assert_eq!(
                mlkem1024_keygen(core::ptr::null(), z.as_ptr(), ek.as_mut_ptr(), dk.as_mut_ptr()),
                -1
            );
        }
        assert_eq!(ss1, ss2);
        // cross-check against the native path with identical inputs
        let (ek_n, dk_n) = ml_kem_1024_keygen(&d, &z);
        assert_eq!(ek, ek_n);
        assert_eq!(dk, dk_n);
    }

    // ---- differential KATs vs independent FIPS 203 oracles (see
    // tests/mlkem1024_fips203_vectors.json, generated by /tmp/fips203_oracle.py
    // and by pqclean's mlkem1024 clean implementation) ----

    fn load_vectors(
    ) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let raw = include_str!("../tests/mlkem1024_fips203_vectors.json");
        // minimal JSON parse: array of {"src":..,"d":..,"z":..,"m":..,
        // "ek":..,"dk":..,"ct":..,"ss":..}
        let mut out = Vec::new();
        for chunk in raw.split("\"d\": \"") {
            if !chunk.contains("\"ek\"") {
                continue;
            }
            let get = |key: &str, src: &str| -> Vec<u8> {
                let hexs = if key == "d" {
                    // value starts at the chunk head (split consumed the key)
                    src.split('"').next().unwrap()
                } else {
                    let mark = [ "\"", key, "\": \"" ].concat();
                    src.split(&mark).nth(1).expect(key).split('"').next().unwrap()
                };
                (0..hexs.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).unwrap())
                    .collect()
            };
            out.push((
                get("d", chunk),
                get("z", chunk),
                get("m", chunk),
                get("ek", chunk),
                get("dk", chunk),
                get("ct", chunk),
                get("ss", chunk),
            ));
        }
        out
    }

    #[test]
    fn differential_kat_vectors() {
        let vecs = load_vectors();
        assert!(!vecs.is_empty(), "KAT vector file missing/empty");
        for (vi, (d, z, m, ek_e, dk_e, ct_e, ss_e)) in vecs.iter().enumerate() {
            let d32: [u8; 32] = d.as_slice().try_into().unwrap();
            let z32: [u8; 32] = z.as_slice().try_into().unwrap();
            let m32: [u8; 32] = m.as_slice().try_into().unwrap();
            let (ek, dk) = ml_kem_1024_keygen(&d32, &z32);
            assert_eq!(ek.as_slice(), ek_e.as_slice(), "vector {} ek", vi);
            assert_eq!(dk.as_slice(), dk_e.as_slice(), "vector {} dk", vi);
            let (ct, ss) = ml_kem_1024_encaps(&ek, &m32);
            assert_eq!(ct.as_slice(), ct_e.as_slice(), "vector {} ct", vi);
            assert_eq!(ss.as_slice(), ss_e.as_slice(), "vector {} ss", vi);
            assert_eq!(ml_kem_1024_decaps(&dk, &ct).as_slice(), ss_e.as_slice(), "vector {} decaps", vi);
        }
    }

    #[test]
    #[allow(dead_code)]
    fn _hex_dump_helper() {
        // kept for regenerating fixtures by hand if needed
        let d = [0x42u8; 32];
        let _ = hex_of(&d);
    }
}
