//! Refreshes the vendored server contract snapshot.
//!
//! The snapshot keeps the test suite independent of sibling repositories.
//! Point `FINGERLY_CONTRACT_DIR` at the integration workspace's contract
//! directory to pull a newer one:
//!
//! ```sh
//! FINGERLY_CONTRACT_DIR=../../contract cargo run --example sync_contract
//! ```
//!
//! `the_snapshot_matches_its_manifest` verifies the result, so there is no
//! separate check mode: `cargo test` is the check.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const FILES: [&str; 2] = ["openapi.json", "fixtures.json"];

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = match std::env::var("FINGERLY_CONTRACT_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => root.join("contract"),
    };
    let target = root.join("contract");

    let manifest_raw = read(&source.join("manifest.json"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_raw)
        .map_err(|error| format!("decode manifest: {error}"))?;

    // Copy only after every file matches the hash the server recorded, so a
    // half-written snapshot cannot land.
    let mut staged: Vec<(&str, Vec<u8>)> = vec![("manifest.json", manifest_raw.clone())];
    for name in FILES {
        let content = read(&source.join(name))?;
        let actual = format!("{:x}", Sha256::digest(&content));
        match manifest.files.get(name) {
            Some(expected) if *expected == actual => staged.push((name, content)),
            _ => return Err(format!("invalid contract hash for {name}: {actual}")),
        }
    }

    std::fs::create_dir_all(&target).map_err(|error| format!("create contract dir: {error}"))?;
    for (name, content) in staged {
        std::fs::write(target.join(name), content)
            .map_err(|error| format!("write {name}: {error}"))?;
    }
    println!("Rust contract snapshot refreshed.");
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}
