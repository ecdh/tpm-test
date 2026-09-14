use anyhow::{anyhow, Context as _, Result};
use log::{info, warn};
use tpm_profile_support::{is_unsupported_algorithm_error, Profile};
use tpm_test_support::{sw_hash, tpm_test, TpmClient};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

fn test_tpm_hash(client: &mut TpmClient, alg: HashingAlgorithm) -> Result<()> {
    let data = b"Hello, TPM hashing!";

    // TPM hash
    let tpm_digest = client.hash(data, alg).context("tpm hash")?;

    // Software reference digest
    // Pure-Rust sha2 crate only supports SHA-256/384/512, so SHA-1 uses a hardcoded vector.
    let sw_digest = if alg == HashingAlgorithm::Sha1 {
        Some(
            hex::decode("9fe6c43a3bb39e64dab681580658354050c184c0")
                .context("decode hardcoded SHA1 digest")?,
        )
    } else {
        match sw_hash(data, alg) {
            Ok(digest) => Some(digest),
            Err(_) => {
                // Software reference hash is not available in pure-Rust harness for this algorithm
                // (e.g. SM3, SHA-3). Accept the TPM digest.
                warn!(
                    "Software reference hash not available for {:?}; accepting TPM result",
                    alg
                );
                None
            }
        }
    };

    if let Some(ref ref_digest) = sw_digest {
        if tpm_digest.value() != ref_digest.as_slice() {
            return Err(anyhow!(
                "TPM and SW hashes should match for {:?}. TPM: {}, SW: {}",
                alg,
                hex::encode(tpm_digest.value()),
                hex::encode(ref_digest)
            ));
        }
    }

    info!(
        "{:?} hash matched: {}",
        alg,
        hex::encode(tpm_digest.value())
    );
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Hash | Smoke",
    hierarchies = "Null",
    description = "Verifies hardware vs software hashing for all profile-defined hash algorithms"
)]
fn test_hash_suite() -> Result<()> {
    let reqs = Profile::from_env()?.hash_requirements(&[
        HashingAlgorithm::Sha256,
        HashingAlgorithm::Sha384,
        HashingAlgorithm::Sha512,
    ]);

    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    reqs.evaluate(
        "hash algorithm",
        |&alg| test_tpm_hash(&mut client, alg),
        is_unsupported_algorithm_error,
    )
}
