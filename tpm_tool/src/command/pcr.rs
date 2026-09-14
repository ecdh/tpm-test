use crate::command::Dispatch;
use anyhow::{anyhow, Context as _, Result};
use num_traits::cast::FromPrimitive;
use tpm_test_support::{HashAlg, TpmClient};
use tss_esapi::structures::{Digest, DigestValues, PcrSelectionListBuilder, PcrSlot};

#[derive(clap::Args, Debug)]
pub struct PcrRead {
    #[arg(long, default_value = "sha256", value_enum)]
    pub alg: HashAlg,
    #[arg(value_name = "PCR")]
    pub pcr: usize,
}

impl Dispatch for PcrRead {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let slot = 1usize
            .checked_shl(self.pcr as u32)
            .and_then(PcrSlot::from_usize)
            .ok_or_else(|| anyhow!("Invalid PCR {}", self.pcr))?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(self.alg.try_into()?, &[slot])
            .build()?;
        let (_count, _list, digests) = client.pcr_read(selection)?;
        for d in digests.value().iter() {
            println!("{}", hex::encode(d.value()));
        }
        Ok(())
    }
}

#[derive(clap::Args, Debug)]
pub struct PcrExtend {
    #[arg(long, default_value = "sha256", value_enum)]
    pub alg: HashAlg,
    #[arg(value_name = "PCR")]
    pub pcr: usize,
    #[arg(value_name = "DIGEST")]
    pub digest: String,
}

impl Dispatch for PcrExtend {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let slot = 1usize
            .checked_shl(self.pcr as u32)
            .and_then(PcrSlot::from_usize)
            .ok_or_else(|| anyhow!("Invalid PCR {}", self.pcr))?;
        let digest = Digest::try_from(hex::decode(&self.digest)?).context("create digest")?;
        let mut values = DigestValues::new();
        values.set(self.alg.try_into()?, digest);

        client.pcr_extend(slot, values).context("extend pcr")?;
        Ok(())
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum Pcr {
    Read(PcrRead),
    Extend(PcrExtend),
}

impl Dispatch for Pcr {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        match self {
            Self::Read(cmd) => cmd.run(client),
            Self::Extend(cmd) => cmd.run(client),
        }
    }
}
