use log::info;
use sha2::{Digest as Sha2Digest, Sha256};
use tpm_test_support::{public_verify, tpm_test, TpmClient};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyDerivationFunctionScheme, Public,
    PublicBuilder, PublicEccParametersBuilder, SignatureScheme,
};
use tss_esapi_sys::{TPMS_CONTEXT, TPMT_TK_HASHCHECK};

fn create_null_hashcheck_ticket() -> HashcheckTicket {
    let raw = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    HashcheckTicket::try_from(raw).expect("create null HashcheckTicket")
}

fn create_ecc_signing_template() -> Public {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .expect("build object attributes");

    let ecc_parameters = PublicEccParametersBuilder::new()
        .with_curve(EccCurve::NistP256)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("build ecc parameters");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("build ecc template")
}

#[tpm_test(
    categories = "Compliance | Session | Asym",
    hierarchies = "Owner",
    description = "Validates TPM2_ContextSave, TPM2_FlushContext, and TPM2_ContextLoad cycle on signing key"
)]
fn test_context_save_load() {
    let mut client = TpmClient::connect_from_env().expect("connect client");
    client.startup_clear().expect("startup clear");

    // Step 1: Create and Load a Volatile Key (The Target)
    let template = create_ecc_signing_template();
    let primary_res = client
        .create_primary(Hierarchy::Owner, template)
        .expect("create primary signing key");
    let key_handle = primary_res.key_handle;
    let out_public = primary_res.out_public;
    info!(
        "Step 1: Created primary key with transient handle: {:?}",
        key_handle
    );

    let message = b"Test message for context save/load";
    let digest_bytes: [u8; 32] = Sha256::digest(message).into();
    let digest = Digest::try_from(digest_bytes.as_slice()).expect("create digest");

    let sig_scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };

    let sig1 = client
        .context
        .execute_with_nullauth_session(|ctx| {
            ctx.sign(
                key_handle,
                digest.clone(),
                sig_scheme,
                create_null_hashcheck_ticket(),
            )
        })
        .expect("sign sanity check");

    let verified = public_verify(&out_public, &sig1, &digest_bytes).expect("verify sig1");
    assert!(verified, "Initial sanity signature verification failed");
    info!("Step 1: Sanity signature operation succeeded and verified");

    // Step 2: Execute TPM2_ContextSave
    let saved_context = client
        .context
        .context_save(ObjectHandle::from(key_handle))
        .expect("context_save");

    let raw_context: TPMS_CONTEXT = TPMS_CONTEXT::try_from(saved_context.clone())
        .expect("convert saved context to TPMS_CONTEXT");

    info!(
        "Step 2: ContextSave output - sequence: {}, savedHandle: 0x{:08X}, hierarchy: 0x{:08X}, blob_size: {}",
        raw_context.sequence,
        raw_context.savedHandle,
        raw_context.hierarchy,
        saved_context.context_blob().len()
    );

    assert!(
        !saved_context.context_blob().is_empty(),
        "Context blob payload must not be empty"
    );

    // Step 3: Evict the Key with TPM2_FlushContext
    client
        .flush_context(ObjectHandle::from(key_handle))
        .expect("flush_context");
    info!("Step 3: Flushed key context with handle {:?}", key_handle);

    let evicted_sign_res = client.context.execute_with_nullauth_session(|ctx| {
        ctx.sign(
            key_handle,
            digest.clone(),
            sig_scheme,
            create_null_hashcheck_ticket(),
        )
    });
    assert!(
        evicted_sign_res.is_err(),
        "Signing with flushed handle must fail"
    );
    info!(
        "Step 3: Verified signing with flushed handle was rejected as expected: {:?}",
        evicted_sign_res.err()
    );

    // Step 4: Reload the Key via TPM2_ContextLoad
    let reloaded_handle = client
        .context
        .context_load(saved_context)
        .expect("context_load");
    let reloaded_key_handle = KeyHandle::from(reloaded_handle);
    info!(
        "Step 4: ContextLoad succeeded, returned active handle: {:?}",
        reloaded_key_handle
    );

    // Step 5: Functional Validation
    let sig2 = client
        .context
        .execute_with_nullauth_session(|ctx| {
            ctx.sign(
                reloaded_key_handle,
                digest.clone(),
                sig_scheme,
                create_null_hashcheck_ticket(),
            )
        })
        .expect("sign with reloaded key handle");

    let verified2 = public_verify(&out_public, &sig2, &digest_bytes).expect("verify sig2");
    assert!(verified2, "Reloaded key signature verification failed");
    info!("Step 5: Signature using reloaded key verified successfully!");

    client
        .flush_context(reloaded_handle)
        .expect("flush reloaded context");
}
