use log::info;
use test_common::{ecc_storage_template, rsa_storage_template};
use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;

#[tpm_test(
    categories = "Compliance | Asym",
    hierarchies = "Owner",
    description = "Creates an RSA-2048 primary storage key under Owner hierarchy"
)]
fn test_create_rsa_primary() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let rsa_template = rsa_storage_template(RsaKeyBits::Rsa2048);
    let res = client
        .create_primary(Hierarchy::Owner, rsa_template)
        .expect("create rsa primary");
    info!("Created RSA Primary Key with handle: {:?}", res.key_handle);
    client
        .flush_context(res.key_handle.into())
        .expect("flush rsa primary");
}

#[tpm_test(
    categories = "Compliance | Asym",
    hierarchies = "Owner",
    description = "Creates an ECC NIST-P256 primary storage key under Owner hierarchy"
)]
fn test_create_ecc_primary() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let ecc_template = ecc_storage_template(EccCurve::NistP256);
    let res = client
        .create_primary(Hierarchy::Owner, ecc_template)
        .expect("create ecc primary");
    info!("Created ECC Primary Key with handle: {:?}", res.key_handle);
    client
        .flush_context(res.key_handle.into())
        .expect("flush ecc primary");
}

#[tpm_test(
    categories = "Compliance | Asym",
    hierarchies = "Owner",
    description = "Verifies that creating a primary key from identical templates produces deterministic names"
)]
fn test_primary_determinism() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let rsa_template = rsa_storage_template(RsaKeyBits::Rsa2048);

    // Create first primary
    let res1 = client
        .create_primary(Hierarchy::Owner, rsa_template.clone())
        .expect("create rsa primary 1");
    let public1 = res1.out_public;
    let (_, name1, _) = client.read_public(res1.key_handle).expect("read public 1");

    // Flush first primary to free slot
    client
        .flush_context(res1.key_handle.into())
        .expect("flush context 1");

    // Create second primary
    let res2 = client
        .create_primary(Hierarchy::Owner, rsa_template)
        .expect("create rsa primary 2");
    let public2 = res2.out_public;
    let (_, name2, _) = client.read_public(res2.key_handle).expect("read public 2");

    client
        .flush_context(res2.key_handle.into())
        .expect("flush context 2");

    assert_eq!(name1, name2, "Primary key names should be identical");
    assert_eq!(
        public1, public2,
        "Primary key public structures should be identical"
    );

    info!("Primary determinism test successful");
}

#[tpm_test(
    categories = "Compliance | Asym",
    hierarchies = "Owner",
    sim_only = true,
    description = "Makes a primary key persistent via EvictControl and verifies across TPM restart"
)]
fn test_persistence() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let persistent_handle = PersistentTpmHandle::new(0x81000001).expect("valid persistent handle");
    if let Ok(existing_handle) = client.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
    {
        let _ = client.evict_control(Hierarchy::Owner, existing_handle, persistent_handle);
    }

    let rsa_template = rsa_storage_template(RsaKeyBits::Rsa2048);
    let res = client
        .create_primary(Hierarchy::Owner, rsa_template)
        .expect("create rsa primary");

    // Make persistent
    client
        .evict_control(Hierarchy::Owner, res.key_handle.into(), persistent_handle)
        .expect("make persistent");

    // Capture the name to verify later
    let (_, name1, _) = client.read_public(res.key_handle).expect("read public 1");

    client
        .flush_context(res.key_handle.into())
        .expect("flush transient handle before restart");

    // Shutdown and Restart (this clears the ESYS context handles but keeps the simulator process)
    client.shutdown_restart().expect("shutdown restart");

    // Re-register the persistent handle in the new context
    let object_handle = client
        .tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
        .expect("tr_from_tpm_public");
    let key_handle = KeyHandle::from(object_handle);

    // Verify key is still there
    let (_, name2, _) = client.read_public(key_handle).expect("read public 2");

    assert_eq!(
        name1, name2,
        "Persistent key name should be the same after restart"
    );

    // Cleanup: evict the persistent key
    client
        .evict_control(Hierarchy::Owner, key_handle.into(), persistent_handle)
        .expect("evict persistent");

    info!("Persistence test successful");
}
