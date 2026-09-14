use anyhow::{Context as _, Result};
use log::info;
use test_common::rsa_storage_template;
use tpm_profile_support::{is_unsupported_algorithm_error, Profile};
use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;

fn test_rsa_key(client: &mut TpmClient, key_bits: RsaKeyBits) -> Result<()> {
    let res = client
        .create_primary(Hierarchy::Owner, rsa_storage_template(key_bits))
        .context(format!("create primary key with key_bits {:?}", key_bits))?;
    info!(
        "Successfully created RSA primary key with key_bits {:?}, handle: {:?}",
        key_bits, res.key_handle
    );
    client.flush_context(res.key_handle.into())?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Asym | Smoke",
    hierarchies = "Owner",
    description = "Verifies RSA key size support for all profile-defined requirement levels"
)]
fn test_rsa_key_suite() -> Result<()> {
    let reqs = Profile::from_env()?.rsa_key_requirements(&[RsaKeyBits::Rsa2048]);

    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    reqs.evaluate(
        "RSA key size",
        |&key_bits| test_rsa_key(&mut client, key_bits),
        is_unsupported_algorithm_error,
    )
}
