# TPM test macros (`tpm_test_macros`)

`tpm_test_macros` provides the `#[tpm_test]` procedural attribute macro for
annotating TPM 2.0 tests with declarative metadata, runtime category filters,
and logging initialization.

## Features

Decorating a test function with `#[tpm_test(...)]`:
1. **Auto-injects `#[test]`**: The standard Rust test harness attribute is
   automatically applied (omitted if the target function is named `main`).
2. **Initializes test logger**: Safely initializes `env_logger` in test capture
   mode (`builder().is_test(true).try_init()`).
3. **Translates test metadata**: Parses test names, descriptions, categories,
   and hierarchies into structured metadata.
4. **Enforces dynamic filter guards**: Injects execution checks
   (`if !__metadata.should_run()`) so tests dynamically skip when filtered out
   by category, exclude-category, hierarchy flags, or `sim_only = true` when
   targeting physical hardware (`TPM_IS_HARDWARE=true`).
5. **Supports `Result<()>` and `()` returns**: Automatically detects whether
   the test function returns `Result<()>` or `()` and generates the appropriate
   early return statement (`return Ok(());` or `return;`).

## Usage examples

### Standard test with defaults

When applied without arguments, `#[tpm_test]` delegates to
`TestCategory::default_categories()` (`Compliance | Smoke`) and
`TestHierarchy::default_hierarchies()` (`Null`):

```rust
use tpm_test_macros::tpm_test;

#[tpm_test]
fn test_startup() {
    // Test logic here
}
```

### Custom metadata and categories

Test categories and hierarchies can be specified using pipe-delimited strings
or string arrays:

```rust
use tpm_test_macros::tpm_test;

#[tpm_test(
    categories = "Compliance | Pcr | Smoke",
    hierarchies = "Null | Owner",
    description = "Extends and verifies PCR banks"
)]
fn test_pcr_extend() -> anyhow::Result<()> {
    // Test logic returning anyhow::Result<()>
    Ok(())
}
```

Array syntax is also supported:

```rust
use tpm_test_macros::tpm_test;

#[tpm_test(
    categories = ["Compliance", "Asym"],
    hierarchies = ["Owner"],
    name = "custom_rsa_test",
    description = "Validates RSA key creation and signing"
)]
fn test_rsa_signing() {
    // Test logic here
}
```

## Testing

Run unit tests for macro parsing and code generation:

```bash
bazel test //tpm_test_macros:tpm_test_macros_test
```
