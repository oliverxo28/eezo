//! executor/mod.rs
//!
//! Entry point for the node-side block execution layer (T54).
//! This module provides:
//!   - `Executor` trait
//!   - `ExecInput` / `ExecOutcome` types
//!   - `SingleExecutor` implementation (serial fallback)
//!   - `ParallelExecutor` implementation (wave-based parallel)
//!   - `StmExecutor` implementation (Block-STM, behind `stm-exec` feature)

mod types;
mod single;
pub mod parallel;

// T73.1: STM executor scaffolding (feature-gated)
#[cfg(feature = "stm-exec")]
pub mod mvhashmap;

#[cfg(feature = "stm-exec")]
pub mod stm;

pub use types::{Executor, ExecInput, ExecOutcome};
pub use single::SingleExecutor;
pub use parallel::ParallelExecutor;

// T73.1: Export StmExecutor when stm-exec feature is enabled
#[cfg(feature = "stm-exec")]
pub use stm::StmExecutor;