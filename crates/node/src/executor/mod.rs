//! executor/mod.rs
//!
//! Entry point for the node-side block execution layer (T54).
//! This module provides:
//!   - `Executor` trait
//!   - `ExecInput` / `ExecOutcome` types
//!   - `SingleExecutor` implementation (serial fallback)

mod types;
mod single;
pub mod parallel;

pub use types::{Executor, ExecInput, ExecOutcome};
pub use single::SingleExecutor;
pub use parallel::ParallelExecutor;