use anyhow::{anyhow, Context as _, Result};
use log::info;
use tpm_profile_support::Profile;
use tpm_test_support::{tpm_test, TpmClient};
use tss_esapi::constants::CommandCode;

#[tpm_test(
    categories = "Compliance | Smoke",
    hierarchies = "Null",
    description = "Verifies command presence and compliance across all profile-defined requirement levels"
)]
fn test_command_suite() -> Result<()> {
    let reqs = Profile::from_env()?.command_requirements(&[
        CommandCode::Startup,
        CommandCode::GetCapability,
        CommandCode::CreatePrimary,
        CommandCode::Create,
        CommandCode::Load,
        CommandCode::ReadPublic,
        CommandCode::FlushContext,
        CommandCode::Quote,
        CommandCode::PcrRead,
        CommandCode::PcrExtend,
        CommandCode::GetRandom,
        CommandCode::Hash,
    ]);

    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let implemented_set = client
        .get_implemented_commands()
        .context("query implemented commands")?;

    info!(
        "TPM capability query returned {} implemented command codes",
        implemented_set.len()
    );

    reqs.evaluate(
        "command",
        |&cmd| {
            if implemented_set.contains(&cmd) {
                Ok(())
            } else {
                Err(anyhow!("Command {:?} not in TPM_CAP_COMMANDS", cmd))
            }
        },
        |_| true,
    )
}
