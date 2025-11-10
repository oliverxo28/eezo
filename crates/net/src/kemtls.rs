//! KEMTLS resumption façade (T37.2).
//! Stable import surface for ticket crypto + replay store.
//! Concrete impls live in `tickets.rs` and `replay.rs`.

// Re-export only what exists in tickets.rs today.
#[cfg(feature = "mlkem")]
pub use crate::tickets::{open_ticket, seal_ticket, ResumeTicketPlain};
// Re-export the sharded replay store facade.
pub use crate::replay::ShardedReplay as TicketReplayStore;
