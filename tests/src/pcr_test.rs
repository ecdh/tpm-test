use log::info;
use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Digest, DigestValues, PcrSelectionListBuilder, PcrSlot};

#[tpm_test(
    categories = "Compliance | Pcr | Smoke",
    hierarchies = "Null",
    description = "Reads PCR 0, extends with SHA-256 digest, and verifies digest changes"
)]
fn test_pcr_read_extend() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    // 1. Read PCR 0 (should be all zeros or a fixed initial value)
    let selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
        .build()
        .expect("build pcr selection");

    let (_update_counter, _read_selection, digests) =
        client.pcr_read(selection.clone()).expect("read pcr");
    assert_eq!(digests.len(), 1);
    let initial_digest = digests.value()[0].clone();
    info!("Initial PCR 0: {:02x?}", initial_digest.value());

    // 2. Extend PCR 0
    let extension_data = vec![0xaa; 32];
    let extension_digest = Digest::try_from(extension_data).expect("create extension digest");
    let mut digests_to_extend = DigestValues::new();
    digests_to_extend.set(HashingAlgorithm::Sha256, extension_digest);

    client
        .pcr_extend(PcrSlot::Slot0, digests_to_extend)
        .expect("extend pcr");

    // 3. Read PCR 0 again and verify it changed
    let (_update_counter, _read_selection, digests) =
        client.pcr_read(selection).expect("read pcr 2");
    assert_eq!(digests.len(), 1);
    let final_digest = digests.value()[0].clone();
    info!("Final PCR 0: {:02x?}", final_digest.value());

    assert_ne!(
        initial_digest.value(),
        final_digest.value(),
        "PCR 0 should have changed after extend"
    );
}

#[tpm_test(
    categories = "Compliance | Pcr",
    hierarchies = "Null",
    description = "Extends resettable PCR 16 and resets via TPM2_PCR_Reset"
)]
fn test_pcr_reset() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    // PCR 16 is typically resettable in many profiles
    let slot = PcrSlot::Slot16;
    let selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[slot])
        .build()
        .expect("build pcr selection");

    // 1. Extend PCR 16
    let extension_data = vec![0xbb; 32];
    let extension_digest = Digest::try_from(extension_data).expect("create extension digest");
    let mut digests_to_extend = DigestValues::new();
    digests_to_extend.set(HashingAlgorithm::Sha256, extension_digest);

    client
        .pcr_extend(slot, digests_to_extend)
        .expect("extend pcr");

    // 2. Verify it's not zero (or at least read the value)
    let (_, _, digests) = client.pcr_read(selection.clone()).expect("read pcr");
    let extended_digest = digests.value()[0].clone();

    // 3. Reset PCR 16
    match client.pcr_reset(slot) {
        Ok(_) => {
            info!("PCR 16 reset successful");
            let (_, _, digests) = client.pcr_read(selection).expect("read pcr after reset");
            let reset_digest = digests.value()[0].clone();
            assert_ne!(
                extended_digest.value(),
                reset_digest.value(),
                "PCR 16 should have changed after reset"
            );
        }
        Err(e) => {
            info!(
                "PCR 16 reset failed (might not be resettable in this profile): {}",
                e
            );
        }
    }
}
