//! Huitzo launcher library surface.
//!
//! This crate normally ships as the `huitzo` binary (see `src/main.rs`).
//! The library target re-exports the modules so integration tests under
//! `tests/` can reach the trust + bundle stack without making each
//! function `pub` only for tests.

pub mod bundle;
pub mod capabilities;
pub mod consent;
pub mod dirs;
pub mod download;
pub mod errors;
pub mod keys;
pub mod manifest;
pub mod prober;
