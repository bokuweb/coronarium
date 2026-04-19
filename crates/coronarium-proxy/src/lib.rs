//! HTTPS MITM proxy that enforces `minimumReleaseAge` at the fetch
//! layer. See the crate README for design + status.

pub mod ca;
pub mod decision;
pub mod install;
pub mod parser;
pub mod proxy;

pub use decision::{AgeOracle, Decider, Decision, RegistryOracle};
pub use parser::{
    CratesIoParser, CratesIoSparseParser, ParseResult, RegistryParser, default_parsers,
    parse_for_host,
};
pub use proxy::{ProxyConfig, run};
