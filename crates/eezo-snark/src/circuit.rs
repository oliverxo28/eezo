#![cfg(feature = "snark-mini")]

// T38.9 — minimal circuit API surface (backend-agnostic).
// Here we only define parameter and witness shells we can swap later.

#[derive(Clone, Debug, Default)]
pub struct MiniCircuitParams {
    /// placeholder knobs; real circuit params go here later
    pub max_queries: usize,
}

#[derive(Clone, Debug)]
pub struct MiniWitness<'a> {
    /// the public object the circuit binds to
    pub packed_words: &'a [u64],
}
