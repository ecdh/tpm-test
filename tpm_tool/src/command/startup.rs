use crate::command::Dispatch;
use anyhow::Result;
use tpm_test_support::TpmClient;

#[derive(clap::Args, Debug)]
pub struct Startup {
    #[arg(long, short)]
    clear: bool,
}

impl Dispatch for Startup {
    fn run(&self, client: &mut TpmClient) -> Result<()> {
        if self.clear {
            client.startup_clear()?;
        } else {
            client
                .context
                .startup(tss_esapi::constants::StartupType::State)?;
        }
        Ok(())
    }
}
