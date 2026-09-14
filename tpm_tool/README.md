# TPM interactive utility (`tpm_tool`)

The `tpm_tool` package provides an interactive command-line interface (CLI) for
manual TPM testing, hardware interaction, and developer experimentation. It is
built on top of the `tpm_test_support` client library to ensure command and
protocol parity with automated test suites.

## Subcommands

- **`startup`**: Issues `TPM2_Startup(CLEAR)` or `TPM2_Startup(STATE)`.
- **`get-random`**: Requests random bytes from the TPM RNG (`TPM2_GetRandom`).
- **`hash`**: Computes SHA-256, SHA-384, or SHA-512 digests on input strings or
  files via `TPM2_Hash`.
- **`pcr`**: Reads or extends Platform Configuration Registers (`TPM2_PCR_Read`,
  `TPM2_PCR_Extend`).
- **`ek`**: Generates primary Endorsement Keys (RSA-2048 or ECC NIST P-256) and
  optionally exports their public keys in DER format.
- **`ecdsa`**: Generates primary ECDSA signing keys on the Owner hierarchy.
- **`quote`**: Executes an end-to-end attestation flow: creates an Endorsement
  Key (EK) and Attestation Key (AK), performs `TPM2_Quote` over a PCR slot,
  verifies the quote signature, and optionally exports the AK and signature.

## Connecting to a TPM

`tpm_tool` connects to a TPM target using the following precedence:

1. Explicit `--tcti` flag (e.g., `--tcti device:/dev/tpmrm0` or
   `--tcti mssim:host=localhost,port=2321`).
2. The `TPM2TOOLS_TCTI` environment variable.
3. Default MSSIM socket endpoints (`--tpm-host 127.0.0.1:2321` and
   `--platform-host 127.0.0.1:2322`).

## Usage examples

```bash
# Request 32 random bytes from a simulator on default MSSIM ports
bazel run //tpm_tool -- get-random 32

# Compute a SHA-256 hash using the TPM
bazel run //tpm_tool -- hash --data "hello world"

# Read PCR slot 10
bazel run //tpm_tool -- pcr read 10

# Create an ECC NIST P-256 Endorsement Key and save the public key
bazel run //tpm_tool -- ek get --ecc nist-p256 --out ek_pub.der

# Perform a PCR quote and verify the attestation signature
bazel run //tpm_tool -- quote 10 --data "nonce-1234"
```
