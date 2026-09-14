# TPM 2.0 compliance integration tests (`tests`)

The `tests` package contains the integration and compliance test suites for
verifying TPM 2.0 implementations against TCG specifications. Each test binary
is wrapped with the `tpm_test_runner` harness, which automatically provisions a
fresh simulator or proxy environment for isolated execution.

## Test suites

- **`startup_test`**: Validates power-on initialization (`TPM2_Startup(CLEAR)`).
- **`pcr_test`**: Validates Platform Configuration Register operations
  (`TPM2_PCR_Read`, `TPM2_PCR_Extend`, and `TPM2_PCR_Reset` on resettable slot
  16).
- **`key_test`**: Validates primary key generation for RSA-2048 and ECC
  NIST P-256 storage keys, primary key template determinism, and key persistence
  across TPM restart via `TPM2_EvictControl`.
- **`context_test`**: Validates transient key context serialization, eviction,
  and restoration (`TPM2_ContextSave`, `TPM2_FlushContext`, and
  `TPM2_ContextLoad`).
- **`attestation_test`**: Validates Endorsement Key (EK) creation, Attestation
  Key (AK) credential activation (`TPM2_MakeCredential` /
  `TPM2_ActivateCredential`), PCR quotes (`TPM2_Quote`), and signature
  verification across RSASSA, RSAPSS, and ECDSA schemes.
- **`nv_test`**: Validates Non-Volatile (NV) space lifecycle
  (`TPM2_NV_DefineSpace`, `TPM2_NV_Write`, `TPM2_NV_Read`,
  `TPM2_NV_ReadPublic`, `TPM2_NV_UndefineSpace`) and data persistence across
  restarts.
- **`cli_test`**: Validates end-to-end `tpm_tool` CLI subcommands (`startup`,
  `get-random`, `hash`, `pcr`, `ek`, and `quote`) against a live TPM.

## Hardware safety and `sim_only` tests

By default, tests are safe to run repeatedly on physical hardware TPMs without
causing flash wear. Individual test functions that perform Non-Volatile (NV)
index allocations or persistent handle writes (`EvictControl`) are annotated
with `sim_only = true` in `#[tpm_test(...)]`. When `TPM_IS_HARDWARE` is not
set, all tests (including `sim_only` tests) execute normally; when
`TPM_IS_HARDWARE=true` is set (such as on `tpm_proxy_environment` targets with
`is_hardware = True`), `TestCaseMetadata::should_run()` automatically skips
`sim_only` test functions while executing all remaining hardware-safe test
functions.

## Running the tests

```bash
# Run the full integration test suite against the TCG TPM simulator
bazel test //tests:rust_integration_tests

# Run an individual wrapped test target
bazel test //tests:rust_integration_tests_key_test_wrapped

# Run the end-to-end CLI integration test
bazel test //tests:rust_integration_tests_cli_test_wrapped

# Run only tests matching a specific category
bazel test //tests:rust_integration_tests --test_env=TPM_TEST_CATEGORY=Attest
```
