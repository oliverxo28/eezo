//! T85.0: Legacy consensus message types (historical reference only)
//!
//! EEZO's consensus in this branch is DAG-primary + STM. HotStuff has been
//! completely removed. This module is retained only for the ValidatorId type
//! which is still used by cert_store and DAG consensus components.
//!
//! See book/src/t81_consensus_history.md for historical context.

use serde::{Deserialize, Serialize};

/// Validator identifier (index into the validator set).
/// Used by cert_store and DAG consensus components.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidatorId(pub u16);