use anyhow::Result;
use tpm_test_support::TpmClient;

pub mod ecdsa;
pub mod ek;
pub mod hash;
pub mod pcr;
pub mod quote;
pub mod random;
pub mod startup;

pub trait Dispatch {
    fn run(&self, client: &mut TpmClient) -> Result<()>;
}

#[derive(clap::Args, Debug)]
pub struct NoOp {
    #[arg(long, short)]
    info: Option<String>,
}

impl Dispatch for NoOp {
    fn run(&self, _client: &mut TpmClient) -> Result<()> {
        if let Some(info) = &self.info {
            log::info!("{info}");
        }
        Ok(())
    }
}
