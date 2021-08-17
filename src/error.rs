//! Error types

use failure::Fail;

pub type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Serialization error: {}", _0)]
    HashSerialize(String),
    #[fail(display = "Option.None an error")]
    NoneError,
}
