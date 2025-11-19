//! executor/mod.rs
//!
//! Entry point for the node-side block execution layer (T52.1).
//! This module provides:
//!   - BlockExecutor trait
//!   - ExecutorRequest / ExecutorOutcome types
//!   - SingleThreadExecutor implementation

mod types;
mod single;

pub use types::{ExecutorRequest, ExecutorOutcome, BlockExecutor};
pub use single::SingleThreadExecutor;
