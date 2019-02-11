
#[macro_use]
pub mod stdio;
pub mod macros;

// export macros, macros appear in top level
// regardless of module hiarachy. this allow us
// `use crate::io` for println, instead of
// `use create::*`.
pub use crate::*;
