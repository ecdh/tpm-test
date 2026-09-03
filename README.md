# TPM 2.0 test suite

This repository contains Rust-based libraries, test harnesses, and tools for
interacting with, testing, and validating Trusted Platform Module 2.0 (TPM 2.0)
implementations against TCG specifications and custom platform profiles.

## Prerequisites

- **Bazel 8.5.1** (or `bazelisk`)
- **OpenSSL development libraries**: Required to link the TCG TPM simulator
  (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora/RHEL).
