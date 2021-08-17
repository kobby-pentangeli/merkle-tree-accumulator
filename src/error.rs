//! Error types

use failure::Fail;

/// Result wrapper
pub type Result<T> = std::result::Result<T, failure::Error>;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    /// Serialization error
    #[fail(display = "Serialization error: {}", _0)]
    HashSerialize(String),
    /// None error
    #[fail(display = "Option.None an error")]
    NoneError,
}
