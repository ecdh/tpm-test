use anyhow::{anyhow, Context as _, Result};
use num_traits::FromPrimitive;

use crate::command::Dispatch;
use tpm_test_support::{
    print_key, print_signature, public_verify, save_key, save_signature, sw_hash, HashAlg,
    TpmClient,
};
use tss_esapi::abstraction::AsymmetricAlgorithmSelection;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::SignatureSchemeAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    AttestInfo, Data, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
};
use tss_esapi::traits::Marshall;

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum Algorithm {
    P256,
    Rsa2048,
    RsaPss2048,
}

impl TryFrom<Algorithm> for AsymmetricAlgorithmSelection {
    type Error = anyhow::Error;
    fn try_from(a: Algorithm) -> Result<Self, Self::Error> {
        match a {
            Algorithm::P256 => Ok(AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)),
            Algorithm::Rsa2048 => Ok(AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)),
            Algorithm::RsaPss2048 => Ok(AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)),
        }
    }
}

impl TryFrom<Algorithm> for SignatureSchemeAlgorithm {
    type Error = anyhow::Error;
    fn try_from(a: Algorithm) -> Result<Self, Self::Error> {
        match a {
            Algorithm::P256 => Ok(SignatureSchemeAlgorithm::EcDsa),
            Algorithm::Rsa2048 => Ok(SignatureSchemeAlgorithm::RsaSsa),
            Algorithm::RsaPss2048 => Ok(SignatureSchemeAlgorithm::RsaPss),
        }
    }
}

impl Algorithm {
    fn as_signature_scheme(&self, alg: HashingAlgorithm) -> Result<SignatureScheme> {
        match self {
            Algorithm::P256 => Ok(SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(alg),
            }),
            Algorithm::Rsa2048 => Ok(SignatureScheme::RsaSsa {
                hash_scheme: HashScheme::new(alg),
            }),
            Algorithm::RsaPss2048 => Ok(SignatureScheme::RsaPss {
                hash_scheme: HashScheme::new(alg),
            }),
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct Quote {
    #[arg(long, default_value = "sha256", value_enum)]
    alg: HashAlg,
    #[arg(long, default_value = "p256", value_enum)]
    signature: Algorithm,
    #[arg(long, default_value = "")]
    data: String,
    #[arg(long)]
    ak_out: Option<String>,
    #[arg(long)]
    sig_out: Option<String>,
    #[arg(value_name = "PCR")]
    pcr: usize,
}

impl Dispatch for Quote {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let ektmpl_alg = AsymmetricAlgorithmSelection::try_from(self.signature)?;
        let ek = client.create_ek(ektmpl_alg).context("create ek")?;
        println!("EK digest = {}", hex::encode(ek.creation_hash.value()));

        let name = client.tr_get_name(ObjectHandle::from(ek.key_handle))?;
        print_key("EK", &name, &ek.out_public)?;

        let hash_alg: HashingAlgorithm = self.alg.try_into()?;
        let (ak_handle, ak_public) = client
            .setup_ak(
                ek.key_handle,
                hash_alg,
                AsymmetricAlgorithmSelection::try_from(self.signature)?,
                SignatureSchemeAlgorithm::try_from(self.signature)?,
            )
            .context("setup ak")?;

        let name = client.tr_get_name(ObjectHandle::from(ak_handle))?;
        print_key("AK", &name, &ak_public)?;
        if let Some(path) = &self.ak_out {
            save_key(path, &ak_public)?;
        }

        let slot = 1usize
            .checked_shl(self.pcr as u32)
            .and_then(PcrSlot::from_usize)
            .ok_or_else(|| anyhow!("Invalid PCR {}", self.pcr))?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &[slot])
            .build()?;

        let scheme = self.signature.as_signature_scheme(hash_alg)?;

        let (attest, signature) = client
            .execute_with_nullauth_session(|ctx| {
                Ok(ctx.quote(
                    ak_handle,
                    Data::try_from(self.data.as_bytes())?,
                    scheme,
                    selection,
                )?)
            })
            .context("quote")?;

        client.flush_context(ak_handle.into())?;
        client.flush_context(ek.key_handle.into())?;

        println!("Quote:");
        println!(
            "  qualified_signer: {}",
            hex::encode(attest.qualified_signer().value())
        );
        println!(
            "  data: {}",
            String::from_utf8_lossy(attest.extra_data().value())
        );
        println!("  clock: {:x?}", attest.clock_info().clock());
        let AttestInfo::Quote { info } = attest.attested() else {
            return Err(anyhow!("not a quote!"));
        };
        println!("  info.pcrs: {:?}", info.pcr_selection());
        println!("  info.digest: {}", hex::encode(info.pcr_digest().value()));
        let rawdata = attest.marshall()?;
        println!("  raw attestation: {}", hex::encode(&rawdata));
        let digest = sw_hash(&rawdata, hash_alg)?;
        println!("  raw digest: {}", hex::encode(&digest));

        print_signature(&signature)?;
        if let Some(path) = &self.sig_out {
            save_signature(path, &signature)?;
        }
        let verified = public_verify(&ak_public, &signature, &digest)
            .context("Verify Error")?;
        println!("Verify: {verified}");
        if !verified {
            anyhow::bail!("Quote signature verification failed");
        }
        Ok(())
    }
}
