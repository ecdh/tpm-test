use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::{NvIndexHandle, NvIndexTpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::structures::{MaxNvBuffer, NvPublicBuilder};

#[tpm_test(
    categories = "Compliance | Nv",
    hierarchies = "Owner",
    sim_only = true,
    description = "Defines, writes, reads, reads public, and undefines standard NV index"
)]
fn test_nv_lifecycle() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let nv_index_u32 = 0x01000001u32;
    let nv_index_tpm = NvIndexTpmHandle::try_from(nv_index_u32).expect("valid nv index tpm");
    if let Ok(existing) = client.tr_from_tpm_public(nv_index_tpm.into()) {
        let _ = client.nv_undefine_space(Provision::Owner, NvIndexHandle::from(existing));
    }

    // 1. Define NV Space
    let attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_pp_read(true)
        .with_no_da(true)
        .build()
        .expect("valid attributes");

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_data_area_size(64)
        .build()
        .expect("valid nv public");

    let nv_index_handle = client
        .nv_define_space(Provision::Owner, nv_public)
        .expect("nv_define_space");

    // 2. Write to NV Space
    let write_data: Vec<u8> = (0..32).collect();
    let write_buffer = MaxNvBuffer::try_from(write_data.clone()).expect("valid max buffer");
    client
        .nv_write(NvAuth::Owner, nv_index_handle, write_buffer, 0)
        .expect("nv_write");

    // 3. Read from NV Space
    let read_buffer = client
        .nv_read(NvAuth::Owner, nv_index_handle, 32, 0)
        .expect("nv_read");
    assert_eq!(&read_buffer[..], write_data.as_slice());

    // 4. Read Public
    let (read_nv_public, _name) = client
        .nv_read_public(nv_index_handle)
        .expect("nv_read_public");
    assert_eq!(read_nv_public.nv_index(), nv_index_tpm);
    assert_eq!(read_nv_public.data_size(), 64);

    // 5. Undefine NV Space
    client
        .nv_undefine_space(Provision::Owner, nv_index_handle)
        .expect("nv_undefine_space");
}

#[tpm_test(
    categories = "Compliance | Nv",
    hierarchies = "Owner",
    sim_only = true,
    description = "Tests NV space data persistence across TPM shutdown and restart"
)]
fn test_nv_persistence() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let nv_index_u32 = 0x01000003u32;
    let nv_index_tpm = NvIndexTpmHandle::try_from(nv_index_u32).expect("valid nv index tpm");
    if let Ok(existing) = client.tr_from_tpm_public(nv_index_tpm.into()) {
        let _ = client.nv_undefine_space(Provision::Owner, NvIndexHandle::from(existing));
    }

    // 1. Define NV Space
    let attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .build()
        .expect("valid attributes");

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_data_area_size(32)
        .build()
        .expect("valid nv public");

    let nv_index_handle = client
        .nv_define_space(Provision::Owner, nv_public)
        .expect("nv_define_space");

    // 2. Write to NV Space
    let write_data = vec![0xdd; 32];
    let write_buffer = MaxNvBuffer::try_from(write_data.clone()).expect("valid max buffer");
    client
        .nv_write(NvAuth::Owner, nv_index_handle, write_buffer, 0)
        .expect("nv_write");

    // 3. Shutdown and Restart TPM (keeps simulator process alive)
    client.shutdown_restart().expect("shutdown restart");

    // 4. Read back and verify
    let nv_index_handle = client
        .tr_from_tpm_public(nv_index_tpm.into())
        .expect("tr_from_tpm_public");
    let nv_index_handle = NvIndexHandle::from(nv_index_handle);

    let read_buffer = client
        .nv_read(NvAuth::Owner, nv_index_handle, 32, 0)
        .expect("nv_read after restart");
    assert_eq!(&read_buffer[..], write_data.as_slice());

    // 5. Cleanup
    client
        .nv_undefine_space(Provision::Owner, nv_index_handle)
        .expect("nv_undefine_space");
}
