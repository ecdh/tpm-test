# TPM profile support library (`tpm_profile_support`)

The `tpm_profile_support` package provides a reusable parser and evaluation
engine for TPM specification profiles and platform SKU configurations. It
enables test targets to load, validate, and evaluate platform requirements
(hash algorithms, RSA key sizes, ECC curves, asymmetric signature schemes,
symmetric ciphers, and command codes) directly from pure JSON5 configuration
files.

By using this library, compliance test suites establish a single, declarative
source of truth matching official TCG Platform Profile specification tables
without requiring hardcoded algorithm matrices or manual CLI flag overrides in
Bazel rules.

## Core concepts

- **`RequirementLevel`**: Enum representing the resolved requirement tier:
  - `Mandatory`: MUST be supported; test fails if missing.
  - `Recommended`: SHOULD be supported; test passes and logs an advisory notice
    if missing.
  - `Optional`: MAY be supported; test executes if supported, and cleanly skips
    if unsupported.
  - `Deprecated`: SHOULD NOT be used for new designs; logs a deprecation notice
    if active.
  - `NotAllowed`: MUST NOT be enabled; test fails if supported by the device.
- **`RequirementGroup<T>`**: Generic container defining items mapped to each of
  the five requirement tiers.
- **`ProfileConfig`**: Struct representing the JSON5 schema for algorithms
  (`hash`, `asymmetric` curves/sizes/schemes, `symmetric`) and `commands`.
- **`Profile`**: The evaluation engine storing requirements in dedicated domain
  maps (`hash_algorithms`, `ecc_curves`, `rsa_key_sizes`, `asymmetric_schemes`,
  `symmetric_ciphers`, `commands`). It applies optional interactive CLI
  overrides and provides typed query methods.

## Example JSON5 profile

```json5
{
  profile_name: "TCG_PC_Client_Profile",
  version: "2.0",

  algorithms: {
    hash: {
      mandatory: ["sha256", "sha384"],
      recommended: ["sha512"],
      optional: ["sm3_256", "sha3_256"],
      not_allowed: ["sha1"]
    },
    asymmetric: {
      rsa_key_sizes: {
        mandatory: [2048],
        recommended: [3072],
        optional: [4096],
        not_allowed: [1024]
      },
      ecc_curves: {
        mandatory: ["nist_p256"],
        recommended: ["nist_p384"],
        optional: ["sm2"]
      },
      algorithms: {
        mandatory: ["rsassa", "ecdsa"],
        optional: ["rsapss"]
      }
    },
    symmetric: {
      mandatory: ["aes128_cfb"],
      recommended: ["aes256_cfb"],
      optional: ["sm4_cfb"]
    }
  },

  commands: {
    mandatory: [
      "TPM2_CC_Startup",
      "TPM2_CC_PCR_Read",
      "TPM2_CC_PCR_Extend",
      "TPM2_CC_CreatePrimary",
      "TPM2_CC_Quote"
    ],
    not_allowed: ["TPM2_CC_FieldUpgrade"]
  }
}
```

## Usage example

```rust
use tpm_profile_support::{Profile, RequirementLevel};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

fn main() -> anyhow::Result<()> {
    // Load profile from TPM_PROFILE_CONFIG environment variable or CLI args
    let profile = Profile::from_env()?;

    // Query status of an algorithm
    if let Some(level) = profile.get_hash_status("sha256") {
        match level {
            RequirementLevel::Mandatory => { /* verify mandatory */ }
            RequirementLevel::Optional => { /* run if supported */ }
            RequirementLevel::NotAllowed => { /* assert unsupported */ }
            _ => {}
        }
    }

    // Retrieve typed collections by status
    let mandatory_hashes: Vec<HashingAlgorithm> =
        profile.get_hashes(RequirementLevel::Mandatory);

    Ok(())
}
```

## Testing

Run the package unit test suite:

```bash
bazel test //tpm_profile_support:tpm_profile_support_test
```

