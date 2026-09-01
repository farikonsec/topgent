//! One integration-test binary for the whole core.
//!
//! Deliberately a single binary rather than one per module: separate binaries
//! each link their own copy of the crate, which splits the coverage profile
//! across instantiations and reports tested code as untested.

mod activity;
mod fixtures;
mod fold;
mod inventory;
mod network;
mod risk;
