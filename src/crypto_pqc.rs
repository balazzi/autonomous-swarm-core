//! Post-quantum lattice primitives over Z_q[X]/(X^256 - 1), q = 3329.
//!
//! Zero-dependency, allocator-free. Provides:
//!   * correct Barrett reduction mod 3329 (verified against `%` in tests)
//!   * forward + inverse Number Theoretic Transform, a full 8-layer 256-point
//!     NTT verified against a naive O(n^2) DFT in tests. The NTT diagonalizes
//!     *cyclic* convolution mod (X^256 - 1) via pointwise multiplication.
//!   * a 4x4 module-matrix state-commit primitive used to seal swarm
//!     ring-buffer transitions in the lattice.
//!
//! Scope note: this is the *primitive layer* (ring arithmetic + NTT +
//! module products), which is what the swarm core needs to seal and verify
//! its own state transitions. It is deliberately NOT Kyber's negacyclic
//! X^256+1 ring. The full FIPS 203 ML-KEM-1024 KEM wire protocol
//! (keygen/encaps/decaps, FO transform, implicit rejection, KAT vectors)
//! lives in [`crate::ml_kem`], with SHA3/SHAKE in [`crate::sha3`].

pub const KYBER_Q: i32 = 3329;
pub const KYBER_N: usize = 256;
/// ML-KEM-1024 module dimension (4x4).
pub const KYBER_K: usize = 4;

/// Primitive 256th root of unity mod 3329: 17^13.
/// 17 is a primitive root mod 3329 (order 3328 = 13*256), so 17^13 has
/// order exactly 256. Verified by `omega_is_primitive_256th_root` test.
pub const NTT_OMEGA: i32 = mod_pow(17, 13, KYBER_Q);
/// Inverse root, for the inverse transform.
pub const NTT_OMEGA_INV: i32 = mod_pow(NTT_OMEGA, KYBER_Q - 2, KYBER_Q);

const fn bit_reverse_u8(mut x: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn mod_pow(base: i32, mut exp: i32, modulus: i32) -> i32 {
    let mut result: i64 = 1;
    let mut b: i64 = (base % modulus) as i64;
    let m = modulus as i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        exp >>= 1;
    }
    result as i32
}

/// A ring element of R_q: polynomial of degree < 256, coefficients in [0, q).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PolyElement {
    pub coefficients: [i16; KYBER_N],
}

impl PolyElement {
    pub const fn zero() -> Self {
        Self {
            coefficients: [0; KYBER_N],
        }
    }

    /// Barrett reduction mod 3329. Quotient via Barrett factor
    /// mu = floor(2^26 / 3329) = 20159, then loop-normalized, so the result
    /// is exact for every i32 input (the loop runs at most a few iterations).
    #[inline(always)]
    pub fn barrett_reduce(val: i32) -> i16 {
        const MU: i64 = 20159; // floor(2^26 / 3329)
        let v = ((val as i64 * MU) >> 26) as i32;
        let mut r = val - v * KYBER_Q;
        while r >= KYBER_Q {
            r -= KYBER_Q;
        }
        while r < 0 {
            r += KYBER_Q;
        }
        r as i16
    }

    /// In-place bit-reversal permutation of the coefficient array.
    fn bitreverse(&mut self) {
        for i in 0..KYBER_N {
            let j = bit_reverse_u8(i as u8) as usize;
            if i < j {
                self.coefficients.swap(i, j);
            }
        }
    }

    /// Ascending decimation-in-time stages (len = 1, 2, ..., 128) under the
    /// given primitive root. Applied to bit-reversed input this yields the
    /// DFT in natural order; it is the single code path shared by both
    /// transform directions.
    fn dit_stages(&mut self, omega: i32) {
        let mut len = 1usize;
        while len <= KYBER_N / 2 {
            // wlen = omega^(256 / (2*len)): primitive 2*len-th root
            let wlen = mod_pow(omega, (KYBER_N / (2 * len)) as i32, KYBER_Q);
            let mut start = 0;
            while start < KYBER_N {
                let mut w: i32 = 1;
                let mut j = start;
                while j < start + len {
                    let t = Self::barrett_reduce(w * self.coefficients[j + len] as i32);
                    let aj = self.coefficients[j] as i32;
                    self.coefficients[j + len] = Self::barrett_reduce(aj - t as i32);
                    self.coefficients[j] = Self::barrett_reduce(aj + t as i32);
                    w = ((w as i64 * wlen as i64) % KYBER_Q as i64) as i32;
                    j += 1;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
    }

    /// Forward NTT. Output[k] = sum_j a[j] * omega^(j*k) mod q, natural order.
    /// Twiddles derive from the true primitive 256th root.
    pub fn forward_ntt(&mut self) {
        self.bitreverse();
        self.dit_stages(NTT_OMEGA);
    }

    /// Inverse NTT: output[j] = n^-1 * sum_k a[k] * omega^(-j*k).
    /// Reuses the forward code path with the inverse root, since
    /// IDFT_omega(y) = n^-1 * DFT_{omega^-1}(y) by definition.
    pub fn inverse_ntt(&mut self) {
        self.bitreverse();
        self.dit_stages(NTT_OMEGA_INV);
        let n_inv = mod_pow(KYBER_N as i32, KYBER_Q - 2, KYBER_Q);
        for c in self.coefficients.iter_mut() {
            *c = Self::barrett_reduce(*c as i32 * n_inv);
        }
    }

    /// Pointwise multiplication in the NTT domain.
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut out = Self::zero();
        for i in 0..KYBER_N {
            out.coefficients[i] =
                Self::barrett_reduce(self.coefficients[i] as i32 * other.coefficients[i] as i32);
        }
        out
    }
}

/// 4x4 module matrix over R_q — the ML-KEM-1024-shaped lattice the swarm
/// uses to seal state transitions.
pub struct ModuleMatrix {
    pub vec: [[PolyElement; KYBER_K]; KYBER_K],
}

impl ModuleMatrix {
    pub const fn new() -> Self {
        Self {
            vec: [[PolyElement::zero(); KYBER_K]; KYBER_K],
        }
    }

    /// Deterministically keys the matrix from a 32-byte seed. A zero matrix
    /// seals every seed to zero, so production deployments must key the
    /// matrix (and ratchet it); this constructor covers bring-up and tests.
    pub fn keyed(seed: &[u8; 32]) -> Self {
        let mut m = Self::new();
        for i in 0..KYBER_K {
            for j in 0..KYBER_K {
                for k in 0..KYBER_N {
                    let v = seed[(k + i * 7 + j * 13) % 32] as i32;
                    m.vec[i][j].coefficients[k] =
                        ((v * (k as i32 + 1) + i as i32 * 31 + j as i32 * 17) % KYBER_Q) as i16;
                }
            }
        }
        m
    }

    /// Seals a 32-byte seed into the lattice: folds the seed into a ring
    /// element, moves to the NTT domain, takes the module dot product with
    /// row 0, and returns to coefficient form. Deterministic — the same
    /// seed and matrix always seal to the same 256-element lattice vector,
    /// which is what makes it usable as a ring-buffer commit tag.
    pub fn encapsulate_state_vector(&self, seed: &[u8; 32], output_lattice: &mut [u16; KYBER_N]) {
        let mut s = PolyElement::zero();
        for i in 0..KYBER_N {
            s.coefficients[i] = (seed[i % 32] as i32 % KYBER_Q as i32) as i16;
        }
        s.forward_ntt();

        let mut acc = PolyElement::zero();
        for j in 0..KYBER_K {
            let mut row = self.vec[0][j];
            row.forward_ntt();
            let prod = row.pointwise_mul(&s);
            for i in 0..KYBER_N {
                acc.coefficients[i] =
                    PolyElement::barrett_reduce(acc.coefficients[i] as i32 + prod.coefficients[i] as i32);
            }
        }
        acc.inverse_ntt();
        for i in 0..KYBER_N {
            output_lattice[i] = acc.coefficients[i] as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omega_is_primitive_256th_root() {
        assert_eq!(mod_pow(NTT_OMEGA, 256, KYBER_Q), 1);
        assert_eq!(mod_pow(NTT_OMEGA, 128, KYBER_Q), KYBER_Q - 1); // omega^128 = -1
        assert_eq!((NTT_OMEGA as i64 * NTT_OMEGA_INV as i64) % KYBER_Q as i64, 1);
    }

    #[test]
    fn barrett_agrees_with_euclidean_mod() {
        let mut a = -4000i32;
        while a < 4000 {
            let mut b = -4000i32;
            while b < 4000 {
                let got = PolyElement::barrett_reduce(a * b) as i32;
                let want = (a as i64 * b as i64).rem_euclid(KYBER_Q as i64) as i32;
                assert_eq!(got, want, "barrett({} * {})", a, b);
                b += 131;
            }
            a += 137;
        }
    }

    #[test]
    fn ntt_roundtrip_is_identity() {
        let mut p = PolyElement::zero();
        for i in 0..KYBER_N {
            p.coefficients[i] = ((i as i32 * 37 + 11) % KYBER_Q) as i16;
        }
        let orig = p;
        p.forward_ntt();
        // NTT of non-constant input must actually move coefficients
        assert_ne!(p.coefficients, orig.coefficients);
        p.inverse_ntt();
        assert_eq!(p.coefficients, orig.coefficients);
    }

    #[test]
    fn ntt_matches_naive_dft() {
        // Reference (natural order): out[k] = sum_j a[j] * omega^(j*k).
        let mut a = [0i64; KYBER_N];
        for i in 0..KYBER_N {
            a[i] = ((i * 131 + 7) % KYBER_Q as usize) as i64;
        }
        let mut p = PolyElement::zero();
        for i in 0..KYBER_N {
            p.coefficients[i] = a[i] as i16;
        }
        p.forward_ntt();
        for k in 0..KYBER_N {
            let mut acc: i64 = 0;
            for j in 0..KYBER_N {
                let e = mod_pow(NTT_OMEGA, ((j * k) % KYBER_N) as i32, KYBER_Q) as i64;
                acc = (acc + a[j] * e) % KYBER_Q as i64;
            }
            assert_eq!(p.coefficients[k] as i64, acc, "slot {}", k);
        }
    }

    #[test]
    fn inverse_ntt_matches_naive_idft() {
        // Naive inverse DFT: a[j] = n^-1 * sum_k A[k] * omega^(-j*k).
        let mut a = [0i64; KYBER_N];
        for i in 0..KYBER_N {
            a[i] = ((i * 57 + 13) % KYBER_Q as usize) as i64;
        }
        let mut p = PolyElement::zero();
        for i in 0..KYBER_N {
            p.coefficients[i] = a[i] as i16;
        }
        p.forward_ntt();
        let n_inv = mod_pow(KYBER_N as i32, KYBER_Q - 2, KYBER_Q) as i64;
        // direct check of inverse_ntt against the naive IDFT of the spectrum
        let mut q = p; // p holds the natural-order spectrum
        q.inverse_ntt();
        for j in 0..KYBER_N {
            let mut acc: i64 = 0;
            for k in 0..KYBER_N {
                let ak = p.coefficients[k] as i64;
                let e = mod_pow(NTT_OMEGA_INV, ((j * k) % KYBER_N) as i32, KYBER_Q) as i64;
                acc = (acc + ak * e) % KYBER_Q as i64;
            }
            acc = (acc * n_inv) % KYBER_Q as i64;
            assert_eq!(q.coefficients[j] as i64, acc, "idft coeff {}", j);
            assert_eq!(q.coefficients[j] as i64, a[j], "roundtrip coeff {}", j);
        }
    }

    #[test]
    fn encapsulate_is_deterministic_and_seed_sensitive() {
        let matrix = ModuleMatrix::keyed(&[0xA5u8; 32]);
        let seed_a = [0xA5u8; 32];
        let seed_b = [0x5Au8; 32];
        let mut out_a1 = [0u16; KYBER_N];
        let mut out_a2 = [0u16; KYBER_N];
        let mut out_b = [0u16; KYBER_N];
        matrix.encapsulate_state_vector(&seed_a, &mut out_a1);
        matrix.encapsulate_state_vector(&seed_a, &mut out_a2);
        matrix.encapsulate_state_vector(&seed_b, &mut out_b);
        assert_eq!(out_a1, out_a2, "sealing must be deterministic");
        assert_ne!(out_a1, out_b, "different seeds must seal differently");
        assert!(out_a1.iter().any(|&x| x != 0), "seal must be non-trivial");
    }

    #[test]
    fn pointwise_mul_matches_naive_cyclic_product_in_ntt_domain() {
        // The NTT diagonalizes *cyclic* convolution mod (X^256 - 1):
        // INTT(NTT(a) .* NTT(b)) == naive cyclic convolution of a and b.
        let mut a = PolyElement::zero();
        let mut b = PolyElement::zero();
        for i in 0..KYBER_N {
            a.coefficients[i] = ((i as i32 * 3 + 1) % 97) as i16;
            b.coefficients[i] = ((i as i32 * 5 + 2) % 89) as i16;
        }
        let mut an = a;
        let mut bn = b;
        an.forward_ntt();
        bn.forward_ntt();
        let mut prod = an.pointwise_mul(&bn);
        prod.inverse_ntt();
        for k in 0..KYBER_N {
            let mut acc: i64 = 0;
            for i in 0..KYBER_N {
                let j = (k + KYBER_N - i) % KYBER_N; // j = (k - i) mod 256
                acc += a.coefficients[i] as i64 * b.coefficients[j] as i64;
            }
            let want = acc.rem_euclid(KYBER_Q as i64) as i16;
            assert_eq!(prod.coefficients[k], want, "coeff {}", k);
        }
    }
}
