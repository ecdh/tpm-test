use crate::command::Dispatch;
use anyhow::Result;
use tpm_test_support::{save_key, EccCurve, TpmClient};
use tss_esapi::abstraction::AsymmetricAlgorithmSelection;
use tss_esapi::interface_types::key_bits::RsaKeyBits;

#[derive(clap::Args, Debug)]
pub struct GetEk {
    #[arg(long)]
    ecc: Option<EccCurve>,
    #[arg(long, short)]
    out: Option<String>,
}

impl Dispatch for GetEk {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let alg = if let Some(curve) = self.ecc {
            AsymmetricAlgorithmSelection::Ecc(curve.try_into()?)
        } else {
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)
        };

        let key = client.create_ek(alg)?;
        println!("key_handle = {:x?}", key.key_handle);
        println!("out_public = {:x?}", key.out_public);
        println!("creation_data = {:x?}", key.creation_data);
        println!("digest = {:x?}", key.creation_hash);

        if let Some(out) = &self.out {
            save_key(out, &key.out_public)?;
        }

        client.flush_context(key.key_handle.into())?;

        Ok(())
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum Ek {
    Get(GetEk),
}

impl Dispatch for Ek {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        match self {
            Self::Get(cmd) => cmd.run(client),
        }
    }
}
