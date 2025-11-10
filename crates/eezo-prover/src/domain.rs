#![cfg(feature = "stark-air")]

// T38.5 — Evaluation domain & LDE scaffold.
// This file defines:
//   - evaluation domain size
//   - blowup factor
//   - primitive roots of unity (omega)
//   - vanishing polynomial on the domain
//
// No FFT or field ops yet — we add those in poly.rs.

use crate::air_spec::params;

/// Evaluation domain parameters.
#[derive(Debug, Clone)]
pub struct Domain {
    /// Base domain size (trace rows rounded to next power-of-two).
    pub size: usize,
    /// Blowup factor for low-degree extension.
    pub blowup: usize,
    /// Generator (root of unity) for the expanded domain.
    pub omega: u64,
}

impl Domain {
    /// Create a domain from a base trace length.
    pub fn new(trace_rows: usize) -> Self {
        let size = trace_rows.next_power_of_two();
        let blowup = params::BLOWUP;
        let omega = Self::primitive_root(size * blowup);

        Self { size, blowup, omega }
    }

    /// Total evaluation domain size.
    pub fn expanded_size(&self) -> usize {
        self.size * self.blowup
    }

    /// Dummy primitive root function (placeholder).
    /// In T38.6 we will swap this with a real Goldilocks-field generator.
    fn primitive_root(n: usize) -> u64 {
        // For now, return a fixed odd number for deterministic tests.
        // (No field arithmetic yet.)
        7 + (n as u64 % 127)
    }

    /// Vanishing polynomial constant term placeholder:
    ///     Z(x) = x^n - 1   (not evaluated yet)
    pub fn vanishing_poly_degree(&self) -> usize {
        self.size
    }
}
