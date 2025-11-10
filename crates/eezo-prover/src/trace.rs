#![cfg(feature = "stark-air")]

// T38.2 — minimal trace container for AIR rows (mock witness).
// Single responsibility: hold rows and basic helpers.
// No hashing/constraints here (added in witness.rs / constraints.rs).

use crate::field::{F, from_u64};
// ✅ FIX: The patch removed this earlier, add again:
use crate::air_spec::{Col, Step};

// count Col variants (keep in sync with air_spec.rs)
pub const N_COLS: usize = 31;

#[inline]
const fn idx(c: Col) -> usize { c as usize }

#[derive(Clone, Debug)]
pub struct Row(pub [F; N_COLS]);

impl Row {
    #[inline]
    pub fn new() -> Self { Self([0u64; N_COLS]) }

    #[inline]
    pub fn set(&mut self, c: Col, v: F) { self.0[idx(c)] = v; }

    #[inline]
    pub fn get(&self, c: Col) -> F { self.0[idx(c)] }

    /// T38.5 — serialize entire row into bytes for hashing.
    #[inline]
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(N_COLS * 8);
        for v in &self.0 {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }
}

#[derive(Clone, Debug, Default)]
pub struct Trace {
    pub rows: Vec<Row>,
}

impl Trace {
    #[inline]
    pub fn new() -> Self { Self { rows: Vec::new() } }

    /// Push a row with a given Step, then let caller fill columns.
    pub fn push_step<F: FnOnce(&mut Row)>(&mut self, step: Step, fill: F) {
        let mut r = Row::new();
        r.set(Col::StepKind, from_u64(step as u64));
        fill(&mut r);
        self.rows.push(r);
    }

    #[inline]
    pub fn last_mut(&mut self) -> &mut Row {
        self.rows.last_mut().expect("trace has at least one row")
    }

    #[inline]
    pub fn last(&self) -> &Row {
        self.rows.last().expect("trace has at least one row")
    }

    #[inline]
    pub fn len(&self) -> usize { self.rows.len() }

    #[inline]
    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
	
    /// T38.5 — required by proof.rs (read-only access to all rows)
    #[inline]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }	

    /// T38.5 — simple row-push helper used only by test scaffolding.
    /// Creates a one-column-like row with StepKind = value,
    /// all other columns remain zero.
    #[inline]
    pub fn push_row(&mut self, value: u64) {
        let mut r = Row::new();
        r.set(Col::StepKind, value);
        self.rows.push(r);
    }
}