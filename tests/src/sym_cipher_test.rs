use anyhow::{anyhow, ensure, Context as _, Result};
use log::info;
use tpm_profile_support::{is_unsupported_algorithm_error, Profile};
use tpm_test_support::{tpm_test, TestRandom, TpmClient};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, InitialValue, MaxBuffer, Public, PublicBuilder, SymmetricCipherParameters,
    SymmetricDefinitionObject,
};

fn create_sym_template(sym_def: SymmetricDefinitionObject) -> Public {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .build()
        .expect("build object attributes");

    let sym_parameters = SymmetricCipherParameters::new(sym_def);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(sym_parameters)
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .expect("build symmetric template")
}

fn get_symmetric_mode(sym_def: SymmetricDefinitionObject) -> SymmetricMode {
    match sym_def {
        SymmetricDefinitionObject::Aes { mode, .. }
        | SymmetricDefinitionObject::Sm4 { mode, .. }
        | SymmetricDefinitionObject::Camellia { mode, .. } => mode,
        SymmetricDefinitionObject::Null => SymmetricMode::Null,
    }
}

/// Tests key creation and roundtrip encryption/decryption across mode-appropriate buffer lengths.
fn test_sym_cipher_suite_for_definition(
    client: &mut TpmClient,
    sym_def: SymmetricDefinitionObject,
) -> Result<()> {
    if sym_def == SymmetricDefinitionObject::Null {
        return Ok(());
    }

    let template = create_sym_template(sym_def);
    let key_res = client
        .create_primary(Hierarchy::Owner, template)
        .context(format!("create primary symmetric key with {:?}", sym_def))?;
    let key_handle = key_res.key_handle;

    info!(
        "Created symmetric primary key with {:?}, handle: {:?}",
        sym_def, key_handle
    );

    let mode = get_symmetric_mode(sym_def);

    // Stream modes (CFB, CTR, OFB) accept arbitrary unaligned byte lengths;
    // block modes (CBC, ECB) require exact multiples of the 16-byte cipher block size.
    let buffer_lengths: &[usize] =
        if matches!(mode, SymmetricMode::Cfb | SymmetricMode::Ctr | SymmetricMode::Ofb) {
            &[7, 15, 16, 24, 256]
        } else {
            &[16, 32, 256]
        };

    let iv = if mode == SymmetricMode::Ecb {
        InitialValue::default()
    } else {
        InitialValue::try_from(vec![0x5au8; 16]).context("create initial IV")?
    };

    let mut rng = TestRandom::from_env();
    let roundtrip_res = (|| -> Result<()> {
        for &len in buffer_lengths {
            let plaintext = rng.random_bytes(len);
            let in_data =
                MaxBuffer::try_from(plaintext.clone()).context("create test plainText buffer")?;

            let (cipher_text, _) = client
                .encrypt_decrypt_2(key_handle, false, mode, in_data, iv.clone())
                .context(format!("encrypt with len {}", len))?;

            let (decrypted_text, _) = client
                .encrypt_decrypt_2(key_handle, true, mode, cipher_text, iv.clone())
                .context(format!("decrypt with len {}", len))?;

            if decrypted_text.value() != plaintext.as_slice() {
                return Err(anyhow!(
                    "Decrypted plaintext mismatch for {:?} at buffer length {}",
                    sym_def,
                    len
                ));
            }
        }

        // Verify non-block-aligned buffer (17 bytes) is rejected for block modes (CBC, ECB).
        if matches!(mode, SymmetricMode::Cbc | SymmetricMode::Ecb) {
            let unaligned = MaxBuffer::try_from(vec![0x42u8; 17]).unwrap();
            let res = client.encrypt_decrypt_2(key_handle, false, mode, unaligned, iv.clone());
            ensure!(
                res.is_err(),
                "Unaligned buffer (17 bytes) unexpectedly succeeded for {:?} ({:?})",
                sym_def,
                mode
            );
        }

        Ok(())
    })();

    let _ = client.flush_context(key_handle.into());
    roundtrip_res?;

    info!(
        "Encryption & Decryption roundtrip verified for {:?} across all payload lengths",
        sym_def
    );

    Ok(())
}

#[tpm_test(
    categories = "Compliance | Sym | Smoke",
    hierarchies = "Owner",
    description = "Verifies symmetric cipher key creation and encrypt/decrypt roundtrips for all profile-defined requirement levels"
)]
fn test_sym_cipher_suite() -> Result<()> {
    let reqs = Profile::from_env()?.symmetric_cipher_requirements(&[
        SymmetricDefinitionObject::AES_128_CFB,
        SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cbc,
        },
    ]);

    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    reqs.evaluate(
        "symmetric cipher",
        |&sym_def| test_sym_cipher_suite_for_definition(&mut client, sym_def),
        is_unsupported_algorithm_error,
    )
}
