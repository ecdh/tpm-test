use crate::command::Dispatch;
use anyhow::{Context as _, Result};
use std::path::PathBuf;
use tpm_test_support::{HashAlg, TpmClient};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

#[derive(clap::Args, Debug)]
pub struct Hash {
    #[arg(long, short, value_enum, default_value_t = HashAlg::Sha256)]
    pub alg: HashAlg,

    #[arg(value_name = "FILE", conflicts_with = "data")]
    pub file: Option<PathBuf>,

    #[arg(long, short)]
    pub data: Option<String>,
}

impl Dispatch for Hash {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let content = if let Some(path) = &self.file {
            std::fs::read(path).with_context(|| format!("Failed to read file: {:?}", path))?
        } else if let Some(data) = &self.data {
            data.as_bytes().to_vec()
        } else {
            return Err(anyhow::anyhow!("Either FILE or --data must be provided"));
        };

        let alg: HashingAlgorithm = self.alg.try_into()?;
        let digest = client.hash(&content, alg)?;

        println!("{}", hex::encode(digest.value()));
        Ok(())
    }
}
