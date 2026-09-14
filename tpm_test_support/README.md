# TPM test support library (`tpm_test_support`)

`tpm_test_support` provides high-level Rust abstractions, common flows, and
metadata management for TPM 2.0 testing. It wraps `tss-esapi` into an idiomatic
client interface (`TpmClient`), discovers runtime capabilities (`TpmConfig`),
and provides category/hierarchy execution filtering (`TestCaseMetadata`).

## Features

- **High-level `TpmClient`**: Simplifies complex multi-command sequences
  (startup, self-test, PCR operations, key generation, signing, NV spaces, and
  quote generation) into atomic, testable flows.
- **Dynamic configuration discovery (`TpmConfig`)**: Interrogates live TPMs
  via `TPM2_GetCapability` and `TPM2_GetProperty` to determine supported
  commands, algorithms, ECC curves, digest sizes, and buffer limits.
- **Structured test metadata (`TestCaseMetadata`)**: Represents test
  categories (`TestCategory`), required hierarchies (`TestHierarchy`), names,
  and descriptions with BitFlags.
- **Runtime execution filtering (`FilterArgs`)**: Dynamically evaluates
  filter criteria from environment variables (`TPM_TEST_CATEGORY`,
  `TPM_TEST_EXCLUDE_CATEGORY`, `TPM_TEST_HIERARCHIES`, `TPM_IS_HARDWARE`) or CLI
  arguments to selectively execute or skip tests (including automatically
  skipping `sim_only` tests on hardware TPMs).
- **Deterministic test RNG (`TestRandom`)**: Seeded pseudo-random number
  generator backed by `fastrand::Rng` for reproducible test vectors,
  configurable via `TPM_TEST_RNG_SEED` (decimal or hex).
- **Macro re-export**: Re-exports `#[tpm_test]` from `tpm_test_macros` alongside
  `BitFlags`, `make_bitflags`, and `env_logger` for seamless test development.

## Key abstractions

### `TpmClient`

Wraps `tss_esapi::Context` with high-level methods:
- `connect_from_env()`: Connects via the `TPM2TOOLS_TCTI` environment variable
  (defaulting to MSSIM simulator).
- `connect(tpm_addr, platform_addr)`: Connects to an explicit MSSIM TCP server
  endpoint.
- `startup_clear()`: Performs full power-on and `TPM2_Startup(SU_CLEAR)`.
- `get_tpm_config()`: Discovers and caches dynamic capabilities.
- `pcr_read()`, `pcr_extend()`, `pcr_reset()`: Convenient PCR bank operations.
- `create_primary()`, `create_rsa_srk_primary()`: Primary key creation under
  Owner or Platform hierarchies.
- `create_ek()`, `setup_ak()`, `quote()`: Common attestation flows.
- `policy_command_code()`, `policy_or()`, `policy_locality()`, `policy_nv()`:
  Compound authorization policy construction and evaluation.

### Test metadata and filtering

- `TestCategory`: Bitflags for `Compliance`, `Extended`, `Pcr`, `Nv`, `Asym`,
  `Sym`, `Hash`, `Attest`, `Policy`, `Session`, `Slow`, and `Smoke`. Provides
  `TestCategory::default_categories()` (`Compliance | Smoke`).
- `TestHierarchy`: Bitflags for `Null`, `Owner`, `Platform`, `Endorsement`, and
  `Lockout`. Provides `TestHierarchy::default_hierarchies()` (`Null`).
- `TestCaseMetadata`: Descriptor evaluated against `FilterArgs` to determine
  whether a test case should run or be skipped.

## Usage examples

### Writing a test with `#[tpm_test]` and `TpmClient`

```rust
use tpm_test_support::tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tpm_test_support::{tpm_test, TpmClient};

#[tpm_test(
    categories = "Compliance | Pcr | Smoke",
    hierarchies = "Null",
    description = "Computes a SHA-256 digest using the TPM"
)]
fn test_hash() -> anyhow::Result<()> {
    let mut client = TpmClient::connect_from_env()?;
    client.startup_clear()?;

    let digest = client.hash(b"test data", HashingAlgorithm::Sha256)?;
    assert!(!digest.value().is_empty());
    Ok(())
}
```

### Filtering test execution

Tests annotated with `#[tpm_test]` automatically read filter configuration
from the test environment:

```bash
# Run only PCR compliance tests
bazel test --test_env=TPM_TEST_CATEGORY="pcr" //...

# Exclude slow tests
bazel test --test_env=TPM_TEST_EXCLUDE_CATEGORY="slow" //...

# Restrict allowed hierarchies to Null and Owner
bazel test --test_env=TPM_TEST_HIERARCHIES="null,owner" //...
```

## Testing

Run unit tests for `tpm_test_support`:

```bash
bazel test //tpm_test_support:tpm_test_support_test
```
