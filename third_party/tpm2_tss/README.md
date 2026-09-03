# TPM2-TSS dependency

This directory contains the Bazel build definition, patch files, and public
aliases for the TPM2 Software Stack (`tpm2-tss` version 4.1.3).

## Contents

- `BUILD.bazel`: Package definition exporting patch files and public alias
  `:tpm2_tss`.
- `BUILD.tpm2_tss.bazel`: Foreign repository overlay defining `configure_make`
  and `cc_library` rules to compile static TSS libraries.
- `0001-version.patch`: Adds version information for hermetic compilation.
- `0002-static-linking.patch`: Guards dynamic TCTI symbol definitions with
  `#ifndef NO_DL` to enable static linking across all TCTI backends.

## Targets

The package exports the following Bazel alias in `//third_party/tpm2_tss`:
- `:tpm2_tss`: Public alias for `@tpm2_tss//:tpm2_tss`, providing static TSS
  libraries (`libtss2-policy.a`, `libtss2-esys.a`, `libtss2-sys.a`,
  `libtss2-tctildr.a`, TCTI backends, `libtss2-mu.a`, and `libtss2-rc.a`).

## Prerequisites

Building `tpm2-tss` via `rules_foreign_cc` executes the project's Autotools
build system and links against OpenSSL for cryptographic operations. The host
system must have Autotools (`autoconf`, `automake`, `libtool`), `pkg-config`,
and OpenSSL development libraries installed:

```bash
# Debian / Ubuntu
sudo apt-get install autoconf automake libtool pkg-config libssl-dev

# Fedora / RHEL
sudo dnf install autoconf automake libtool pkgconf-pkg-config openssl-devel
```

## Usage

```bash
bazel build //third_party/tpm2_tss/...
```
