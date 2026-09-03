# TCG TPM dependency

This directory contains the Bazel build definition and patches for the
Trusted Computing Group (TCG) TPM reference implementation (version
[v184](https://github.com/TrustedComputingGroup/TPM/releases/tag/V184)).

## Contents

- `BUILD.bazel`: Local package definition exporting patch files and public
  aliases (`:tcg_tpm`, `:tpm_headers`, `:tpm_configuration`).
- `BUILD.tcg_tpm.bazel`: Foreign repository overlay defining native Bazel
  `cc_library` and `cc_binary` build rules for TPM core, crypto, platform,
  configuration, and simulator components.
- `0001-openssl-version.patch`: Updates OpenSSL version check to allow
  compilation on modern OpenSSL (3.x/4.x).
- `0002-compiler-fixes.patch`: Fixes compilation issues when certain algorithms
  (e.g., `ALG_RSA`, `ALG_ECC`, `ALG_ECDAA`, `ALG_ECSCHNORR`) are conditionally
  enabled or disabled.

## Targets

The package exports the following Bazel aliases in `//third_party/tcg_tpm`:
- `:tcg_tpm`: The standalone TPM 2.0 TCP socket simulator binary
  (`@tcg_tpm//:tcg_tpm`).
- `:tpm_headers`: All TPM 2.0 reference headers (`tpm_public`,
  `platform_interface`, `private`) required to compile custom configurations.
- `:tpm_configuration`: Configurable `label_flag` allowing downstream
  repositories to inject custom command lists, algorithms, and vendor command
  handlers.

## Prerequisites

The TCG TPM simulator links against OpenSSL for cryptographic primitives
(`-lcrypto`). Ensure `libssl-dev` (Debian/Ubuntu) or `openssl-devel`
(Fedora/RHEL) is installed on the host system:

```bash
# Debian / Ubuntu
sudo apt-get install libssl-dev

# Fedora / RHEL
sudo dnf install openssl-devel
```

## Usage

### Building the default simulator

```bash
bazel build //third_party/tcg_tpm
```

### Overriding configuration in downstream repositories

Downstream repositories can override the configuration by pointing the
`tpm_configuration` label flag to a custom `cc_library`:

```bash
bazel build \
  --@tpm_test//third_party/tcg_tpm:tpm_configuration=//custom_config:my_tpm_configuration \
  //third_party/tcg_tpm
```
