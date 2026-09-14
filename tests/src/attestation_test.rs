use log::info;
use sha2::{Digest, Sha256};
use tpm_test_support::{public_verify, tpm_test, TpmClient};
use tss_esapi::abstraction::AsymmetricAlgorithmSelection;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    AttestInfo, Data, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
};
use tss_esapi::traits::Marshall;

#[tpm_test(
    categories = "Compliance | Attest | Asym",
    hierarchies = "Endorsement",
    description = "Creates an Endorsement Key (EK) from default TCG template"
)]
fn test_ek_creation() {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    let ek_res = client
        .create_ek(AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048))
        .expect("create ek");
    info!("Created EK with handle: {:?}", ek_res.key_handle);
    client
        .flush_context(ek_res.key_handle.into())
        .expect("flush ek");
}

fn run_attestation_test(asym_alg: AsymmetricAlgorithmSelection, sig_alg: SignatureSchemeAlgorithm) {
    let mut client = TpmClient::connect_from_env().expect("connect client");

    client.startup_clear().expect("startup clear");

    // 1. Create EK
    let ek_res = client.create_ek(asym_alg).expect("create ek");
    let ek_handle = ek_res.key_handle;

    // 2. Create and Setup AK (includes Load and Activate)
    let (ak_handle, ak_public) = client
        .setup_ak(ek_handle, HashingAlgorithm::Sha256, asym_alg, sig_alg)
        .expect("setup ak");

    // 3. Quote
    let slot = PcrSlot::Slot0;
    let selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[slot])
        .build()
        .expect("pcr selection");

    let scheme = match sig_alg {
        SignatureSchemeAlgorithm::RsaSsa => SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        },
        SignatureSchemeAlgorithm::RsaPss => SignatureScheme::RsaPss {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        },
        SignatureSchemeAlgorithm::EcDsa => SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        },
        _ => panic!("Unsupported signature algorithm"),
    };

    let (attest, signature) = client
        .context
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(
                ak_handle,
                Data::try_from(b"extra data".to_vec()).expect("data"),
                scheme,
                selection,
            )
        })
        .expect("quote");

    client
        .flush_context(ak_handle.into())
        .expect("flush ak handle");
    client
        .flush_context(ek_handle.into())
        .expect("flush ek handle");

    info!("Quote successful");
    let AttestInfo::Quote { info } = attest.attested() else {
        panic!("not a quote!");
    };
    info!("Quote PCR Digest: {:02x?}", info.pcr_digest().value());

    // 4. Verify Signature
    let rawdata = attest.marshall().expect("marshall attest");
    let digest = Sha256::digest(&rawdata);

    let verified = public_verify(&ak_public, &signature, &digest).expect("public verify");
    assert!(verified, "Signature verification failed");
}

#[tpm_test(
    categories = "Compliance | Attest | Asym",
    hierarchies = "Owner | Endorsement",
    description = "Generates RSASSA Quote and verifies signature over PCR digest"
)]
fn test_ak_and_quote_rsa() {
    run_attestation_test(
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaSsa,
    );
}

#[tpm_test(
    categories = "Compliance | Attest | Asym",
    hierarchies = "Owner | Endorsement",
    description = "Generates RSAPSS Quote and verifies signature over PCR digest"
)]
fn test_ak_and_quote_rsa_pss() {
    run_attestation_test(
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
    );
}

#[tpm_test(
    categories = "Compliance | Attest | Asym",
    hierarchies = "Owner | Endorsement",
    description = "Generates ECDSA Quote with NIST-P256 and verifies signature over PCR digest"
)]
fn test_ak_and_quote_ecc() {
    run_attestation_test(
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        SignatureSchemeAlgorithm::EcDsa,
    );
}
