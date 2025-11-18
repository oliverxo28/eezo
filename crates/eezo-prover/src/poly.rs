// T38.5 — Minimal polynomial backend.
// This provides:
//   - Polynomial struct
//   - add, scale, mul-by-monomial
//   - interpolation stub (deterministic placeholder)
//   - evaluation over the expanded domain (using Domain)
//
// Real FFTs + proper polynomial arithmetic will be added in T38.6/T38.7.

use crate::domain::Domain;

/// A simple polynomial represented by coefficients:
///     p(x) = coeffs[0] + coeffs[1]·x + ...
#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coeffs: Vec<u64>,  // Goldilocks will replace this later
}

impl Polynomial {
    /// Create a zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: vec![0] }
    }

    /// Degree of the polynomial (ignores trailing zeros).
    pub fn degree(&self) -> usize {
        let mut d = 0;
        for (i, c) in self.coeffs.iter().enumerate() {
            if *c != 0 {
                d = i;
            }
        }
        d
    }

    /// Add two polynomials coefficient-wise.
    pub fn add(&self, other: &Self) -> Self {
        let n = self.coeffs.len().max(other.coeffs.len());
        let mut out = vec![0u64; n];

        for i in 0..n {
            let a = *self.coeffs.get(i).unwrap_or(&0);
            let b = *other.coeffs.get(i).unwrap_or(&0);
            out[i] = a.wrapping_add(b);  // Goldilocks-friendly later
        }

        Self { coeffs: out }
    }

    /// Multiply polynomial by scalar.
    pub fn scale(&self, k: u64) -> Self {
        let out = self
            .coeffs
            .iter()
            .map(|c| c.wrapping_mul(k))
            .collect::<Vec<_>>();

        Self { coeffs: out }
    }

    /// Multiply by x^n (i.e. shift coefficients).
    pub fn mul_xn(&self, n: usize) -> Self {
        if self.coeffs == vec![0] {
            return Self::zero();
        }
        let mut out = vec![0u64; n];
        out.extend_from_slice(&self.coeffs);
        Self { coeffs: out }
    }

    // -------------------------------------------------------------------------
    // T38.5 — Interpolation (placeholder)
    // -------------------------------------------------------------------------
    // This will later use FFT. For now, produce deterministic result so tests can run.
    pub fn interpolate(values: &[u64]) -> Self {
        // For deterministic behavior:
        // Interpret the input values directly as coefficients.
        // This is *not* mathematically correct but allows LDE + FRI scaffolding to compile.
        Self { coeffs: values.to_vec() }
    }

    // -------------------------------------------------------------------------
    // T38.5 — Evaluation over the expanded domain (LDE)
    // -------------------------------------------------------------------------
    pub fn evaluate_over(&self, domain: &Domain) -> Vec<u64> {
        let n = domain.expanded_size();
        let mut evals = Vec::with_capacity(n);

        // VERY simple placeholder evaluation:
        //     p(i) = sum(coeff[j] * (i+1)^j)
        //
        // (again deterministic, replaced later with FFT domain evaluation)
        for i in 0..n {
            let x = (i as u64) + 1;
            let mut acc = 0u64;

            for (j, &c) in self.coeffs.iter().enumerate() {
                let mut pow = 1u64;
                for _ in 0..j {
                    pow = pow.wrapping_mul(x);
                }
                acc = acc.wrapping_add(c.wrapping_mul(pow));
            }

            evals.push(acc);
        }

        evals
    }
}
