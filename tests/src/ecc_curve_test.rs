use anyhow::{Context as _, Result};
use log::info;
use test_common::ecc_storage_template;
use tpm_profile_support::{is_unsupported_algorithm_error, Profile};
use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;

fn test_ecc_curve(client: &mut TpmClient, curve: EccCurve) -> Result<()> {
    let res = client
        .create_primary(Hierarchy::Owner, ecc_storage_template(curve))
        .context(format!("create primary key with curve {:?}", curve))?;
    info!(
        "Successfully created primary key with curve {:?}, handle: {:?}",
        curve, res.key_handle
    );
    client.flush_context(res.key_handle.into())?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Asym | Smoke",
    hierarchies = "Owner",
    description = "Verifies ECC curve support for all profile-defined requirement levels"
)]
fn test_ecc_curve_suite() -> Result<()> {
    let reqs = Profile::from_env()?.ecc_curve_requirements(&[EccCurve::NistP256]);

    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    reqs.evaluate(
        "ECC curve",
        |&curve| test_ecc_curve(&mut client, curve),
        is_unsupported_algorithm_error,
    )
}
