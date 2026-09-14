use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    EccPoint, EccScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
    SymmetricDefinitionObject,
};

/// Builds a standard restricted RSA storage key template (`AES_128_CFB`, `SHA-256` name hash).
pub fn rsa_storage_template(key_bits: RsaKeyBits) -> Public {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("build object attributes");

    let rsa_parameters = PublicRsaParametersBuilder::new()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_is_signing_key(false)
        .with_key_bits(key_bits)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_scheme(RsaScheme::Null)
        .build()
        .expect("build rsa parameters");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("build rsa template")
}

/// Builds a standard restricted ECC storage key template (`AES_128_CFB`, `SHA-256` name hash).
pub fn ecc_storage_template(curve: EccCurve) -> Public {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("build object attributes");

    let ecc_parameters = PublicEccParametersBuilder::new()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_is_signing_key(false)
        .with_curve(curve)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
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
