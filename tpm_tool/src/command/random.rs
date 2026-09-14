use crate::command::Dispatch;
use anyhow::Result;
use tpm_test_support::TpmClient;

#[derive(clap::Args, Debug)]
pub struct GetRandom {
    #[arg(value_name = "NUM_BYTES")]
    pub n: usize,
}

impl Dispatch for GetRandom {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        let result = client.get_random(self.n)?;
        println!("{}", hex::encode(result));
        Ok(())
    }
}
