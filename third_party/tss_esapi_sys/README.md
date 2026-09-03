# tss-esapi-sys dependency

This directory contains the Bazel build definition and overlay for
`tss-esapi-sys` fetched from upstream
[`parallaxsecond/rust-tss-esapi`](https://github.com/parallaxsecond/rust-tss-esapi).

## Contents

- `BUILD.bazel`: Package definition exporting the public alias `:tss_esapi_sys`.
- `BUILD.tss_esapi_sys.bazel`: Foreign repository overlay defining native
  `rust_library` rules that link against `@tpm_test//third_party/tpm2_tss`.

## Targets

- `//third_party/tss_esapi_sys:tss_esapi_sys`: Public alias for
  `@tss_esapi_sys//:tss_esapi_sys`, providing low-level Rust FFI bindings to
  TPM2-TSS.

## Integration

In `MODULE.bazel`, `crate_universe` uses
`override_target_lib = "//third_party/tss_esapi_sys:tss_esapi_sys"` to route
all `tss-esapi` crate dependencies to this hermetic target, eliminating
the need for `cargo_build_script` or `inject_repo`.
