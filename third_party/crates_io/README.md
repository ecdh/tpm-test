# crates.io dependencies

This directory manages external Rust crate dependencies via `rules_rust` and
`crate_universe`.

## Contents

- `Cargo.toml`: Manifest declaring direct third-party Rust dependencies.
- `Cargo.lock`: Pinning lockfile for reproducible dependency resolution.
- `fake.rs`: Minimal empty library root required by Cargo to resolve the
  workspace member.
- `BUILD.bazel`: Package definition exporting the Cargo manifests to Bazel.

## Integration

`MODULE.bazel` consumes `Cargo.toml` and `Cargo.lock` via
`crate.from_cargo(name = "tpm_test_crates", ...)`.
