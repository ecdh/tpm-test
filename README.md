# TPM 2.0 test suite

This repository contains Rust-based libraries, test harnesses, and tools for
interacting with, testing, and validating Trusted Platform Module 2.0 (TPM 2.0)
implementations against TCG specifications and custom platform profiles.

## Project structure

- `third_party/`: Third-party dependencies including native `tcg_tpm`,
  static `tpm2_tss`, `tss_esapi_sys` FFI, and pinned Rust crates.
- `tpm_profile_support/`: Platform profile and algorithm requirement parser
  evaluating JSON5 specifications against runtime TPM capabilities.
- `tpm_proxy/`: Extensible TCP TPM proxy engine (`tpm_proxy_lib` + `tpm_proxy`
  binary) implementing the MSSIM protocol for hardware devboards, sockets,
  and simulators.
- `tpm_test_macros/`: Procedural macro crate providing `#[tpm_test]` attribute
  for test metadata annotation, category filtering, and log initialization.
- `tpm_test_runner/`: Unified Bazel test execution framework with dynamic
  simulator lifecycle management, port allocation, and late-bound test
  environments.
- `tpm_test_support/`: High-level TPM client library (`TpmClient`), dynamic
  capability discovery (`TpmConfig`), and metadata filtering framework.
- `tpm_tool/`: Interactive command-line utility (`tpm_tool`) for manual TPM
  operations, hashing, PCR read/extend, key creation, and quote verification.
- `tests/`: Compliance and integration test suites validating TPM 2.0
  behavior against TCG specifications and custom platform profiles.

## Prerequisites

- **Bazel 8.5.1** (or `bazelisk`)
- **OpenSSL development libraries**: Required to link the TCG TPM simulator and
  TPM2-TSS libraries (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on
  Fedora/RHEL).
- **Autotools and pkg-config**: Required to build the foreign `tpm2-tss`
  dependency via `rules_foreign_cc` (`autoconf`, `automake`, `libtool`,
  `pkg-config` on Debian/Ubuntu; `autoconf`, `automake`, `libtool`,
  `pkgconf-pkg-config` on Fedora/RHEL).
