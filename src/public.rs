//! Public interface for integration with other systems

use crate::actor::{VaultActor, VaultEvent};

pub use crate::actor::VaultActor;
pub use crate::actor::VaultEvent;

// Re-export message types for cross-crate actor communication
pub use crate::actor::{
    CheckStatus,
    InitVault,
    UnsealVault,
    SetupTransit,
    StatusInfo,
};