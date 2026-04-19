//! HTTPS MITM proxy that enforces `minimumReleaseAge` at the fetch
//! layer. See the crate README for design + status.

pub mod ca;
pub mod decision;
pub mod install;
pub mod parser;
pub mod proxy;
pub mod rewrite;
pub mod rewrite_npm;
pub mod rewrite_pypi;

pub use decision::{AgeOracle, Decider, Decision, RegistryOracle};
pub use parser::{
    CratesIoParser, CratesIoSparseParser, ParseResult, RegistryParser, default_parsers,
    parse_for_host,
};
pub use proxy::{ProxyConfig, run};
pub use rewrite::{RewriteStats, rewrite_crates_index_jsonl};
pub use rewrite_npm::{NpmRewriteStats, rewrite_npm_packument};
pub use rewrite_pypi::{PypiRewriteStats, rewrite_pypi_json_api, rewrite_pypi_simple_json};
