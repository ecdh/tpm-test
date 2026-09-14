use crate::command::Dispatch;
use anyhow::Result;
use tpm_test_support::{save_key, EccCurve, TpmClient};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    EccPoint, EccScheme, HashScheme, PublicBuilder, PublicEccParametersBuilder,
};

#[derive(clap::Args, Debug)]
pub struct CreateEcdsa {
    #[arg(long, value_enum, default_value_t = EccCurve::NistP256)]
    curve: EccCurve,
    #[arg(long, short)]
    out: Option<String>,
}

impl Dispatch for CreateEcdsa {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let ecc_curve: tss_esapi::interface_types::ecc::EccCurve = self.curve.try_into()?;
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()?;
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_unrestricted_signing_key(
                    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                    ecc_curve,
                )
                .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;
        let primary = client.create_primary(Hierarchy::Owner, public)?;
        println!("key_handle = {:x?}", primary.key_handle);
        if let Some(out) = &self.out {
            save_key(out, &primary.out_public)?;
        }
        client.flush_context(primary.key_handle.into())?;
        Ok(())
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum Ecdsa {
    Create(CreateEcdsa),
}

impl Dispatch for Ecdsa {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.run(client),
        }
    }
}
