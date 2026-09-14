use std::collections::HashMap;

use anyhow::{anyhow, ensure, Context as _, Result};
use log::info;
use tpm_test_support::{sw_hash, tpm_test, TestRandom, TpmClient};
use tss_esapi::attributes::{LocalityAttributes, NvIndexAttributesBuilder, ObjectAttributesBuilder};
use tss_esapi::constants::tss::{TPM2_RH_OWNER, TPM2_ST_VERIFIED};
use tss_esapi::constants::CommandCode;
use tss_esapi::handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    Auth, Digest, DigestList, DigestValues, HashScheme, MaxNvBuffer, Nonce, NvPublicBuilder,
    PcrSelectionListBuilder, PcrSlot, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
    RsaScheme, RsaSignature, Signature, SignatureScheme, SymmetricDefinitionObject, VerifiedTicket,
};

fn sha256_concat(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut data = Vec::with_capacity(total_len);
    for part in parts {
        data.extend_from_slice(part);
    }
    sw_hash(&data, HashingAlgorithm::Sha256).unwrap()
}

fn cc_bytes(cc: CommandCode) -> [u8; 4] {
    u32::from(cc).to_be_bytes()
}

/// Software oracle for TPM2_PolicyCommandCode according to TCG Specification Part 1:
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyCommandCode || code )
fn sw_policy_command_code(current_digest: &[u8], code: CommandCode) -> Vec<u8> {
    sha256_concat(&[
        current_digest,
        &cc_bytes(CommandCode::PolicyCommandCode),
        &cc_bytes(code),
    ])
}

/// Software oracle for TPM2_PolicyLocality according to TCG Specification Part 1:
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyLocality || locality )
fn sw_policy_locality(current_digest: &[u8], locality: LocalityAttributes) -> Vec<u8> {
    sha256_concat(&[
        current_digest,
        &cc_bytes(CommandCode::PolicyLocality),
        &[u8::from(locality)],
    ])
}

/// Software oracle for TPM2_PolicyOR according to TCG Specification Part 1:
/// policyDigest_new = SHA256( zeros || TPM_CC_PolicyOR || branch_0 || branch_1 ... )
fn sw_policy_or(branch_digests: &[&[u8]]) -> Vec<u8> {
    let cc = cc_bytes(CommandCode::PolicyOr);
    let mut parts: Vec<&[u8]> = vec![&[0u8; 32], &cc];
    parts.extend_from_slice(branch_digests);
    sha256_concat(&parts)
}

/// Software oracle for TPM2_PolicyAuthValue / TPM2_PolicyPassword according to TCG Specification Part 1:
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyAuthValue )
fn sw_policy_auth_value(current_digest: &[u8]) -> Vec<u8> {
    sha256_concat(&[current_digest, &cc_bytes(CommandCode::PolicyAuthValue)])
}

/// Software oracle for TPM2_PolicyNV according to TCG Specification Part 1:
/// args = SHA256( operandB || offset_be || operation_be )
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyNV || args || nv_name )
fn sw_policy_nv(
    current_digest: &[u8],
    nv_name: &[u8],
    operand_b: &[u8],
    offset: u16,
    operation: u16,
) -> Vec<u8> {
    let args_hash = sha256_concat(&[operand_b, &offset.to_be_bytes(), &operation.to_be_bytes()]);
    sha256_concat(&[
        current_digest,
        &cc_bytes(CommandCode::PolicyNv),
        &args_hash,
        nv_name,
    ])
}

/// Software oracle for TPM2_PolicyCounterTimer according to TCG Specification Part 1:
/// args = SHA256( operandB || offset_be || operation_be )
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyCounterTimer || args )
fn sw_policy_counter_timer(
    current_digest: &[u8],
    operand_b: &[u8],
    offset: u16,
    operation: u16,
) -> Vec<u8> {
    let args_hash = sha256_concat(&[operand_b, &offset.to_be_bytes(), &operation.to_be_bytes()]);
    sha256_concat(&[
        current_digest,
        &cc_bytes(CommandCode::PolicyCounterTimer),
        &args_hash,
    ])
}

/// Software oracle for TPM2_PolicySigned according to TCG Specification Part 1:
/// step1 = SHA256( policyDigest_old || TPM_CC_PolicySigned || authKeyName )
/// policyDigest_new = SHA256( step1 || policyRef )
fn sw_policy_signed(current_digest: &[u8], key_name: &[u8], policy_ref: Option<&[u8]>) -> Vec<u8> {
    let step1 = sha256_concat(&[current_digest, &cc_bytes(CommandCode::PolicySigned), key_name]);
    sha256_concat(&[&step1, policy_ref.unwrap_or(&[])])
}

/// Software oracle for TPM2_PolicyAuthorize according to TCG Specification Part 1:
/// step1 = SHA256( zeros || TPM_CC_PolicyAuthorize || keySign )
/// policyDigest_new = SHA256( step1 || policyRef )
fn sw_policy_authorize(key_sign: &[u8], policy_ref: Option<&[u8]>) -> Vec<u8> {
    let step1 = sha256_concat(&[&[0u8; 32], &cc_bytes(CommandCode::PolicyAuthorize), key_sign]);
    sha256_concat(&[&step1, policy_ref.unwrap_or(&[])])
}

/// Software oracle for TPM2_PolicyCpHash according to TCG Specification Part 1:
/// policyDigest_new = SHA256( policyDigest_old || TPM_CC_PolicyCpHash || cpHash )
fn sw_policy_cp_hash(current_digest: &[u8], cp_hash: &[u8]) -> Vec<u8> {
    sha256_concat(&[
        current_digest,
        &cc_bytes(CommandCode::PolicyCpHash),
        cp_hash,
    ])
}

#[tpm_test(
    categories = "Compliance | Policy | Smoke",
    hierarchies = "Owner",
    description = "Verifies multi-branch policy OR with locality constraints against software oracle and session restart"
)]
fn test_policy_1() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let srk_handle = client.create_rsa_srk_primary().context("create SRK")?;

    // --- Independent Software Ground Truth Calculation ---
    let initial_zeros = [0u8; 32];

    // Branch 0 (SW): PolicyCommandCode(Unseal) -> PolicyLocality(LocZero)
    let sw_b0_step1 = sw_policy_command_code(&initial_zeros, CommandCode::Unseal);
    let sw_b0 = sw_policy_locality(&sw_b0_step1, LocalityAttributes::LOCALITY_ZERO);

    // Branch 1 (SW): PolicyLocality(LocThree) -> PolicyCommandCode(Unseal)
    let sw_b1_step1 = sw_policy_locality(&initial_zeros, LocalityAttributes::LOCALITY_THREE);
    let sw_b1 = sw_policy_command_code(&sw_b1_step1, CommandCode::Unseal);

    // Root PolicyOR (SW)
    let sw_expected_or = sw_policy_or(&[&sw_b0, &sw_b1]);

    info!(
        "Software computed PolicyOR ground truth digest: {}",
        hex::encode(&sw_expected_or)
    );

    // --- TPM Trial Session Verification Against Software Oracle ---
    // 1. Calculate Branch 0 on TPM
    let (t0_sess, t0_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(t0_pol, CommandCode::Unseal)?;
    client.policy_locality(t0_pol, LocalityAttributes::LOCALITY_ZERO)?;
    let digest_b0 = client.policy_get_digest(t0_pol)?;
    client.flush_session(t0_sess)?;

    if digest_b0.value() != sw_b0.as_slice() {
        return Err(anyhow!(
            "TPM Branch 0 trial digest ({}) did not match software oracle ({})",
            hex::encode(digest_b0.value()),
            hex::encode(&sw_b0)
        ));
    }

    // 2. Calculate Branch 1 on TPM
    let (t1_sess, t1_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_locality(t1_pol, LocalityAttributes::LOCALITY_THREE)?;
    client.policy_command_code(t1_pol, CommandCode::Unseal)?;
    let digest_b1 = client.policy_get_digest(t1_pol)?;
    client.flush_session(t1_sess)?;

    if digest_b1.value() != sw_b1.as_slice() {
        return Err(anyhow!(
            "TPM Branch 1 trial digest ({}) did not match software oracle ({})",
            hex::encode(digest_b1.value()),
            hex::encode(&sw_b1)
        ));
    }

    // 3. Calculate PolicyOR(Branch 0, Branch 1) on TPM
    let mut digest_list = DigestList::new();
    digest_list.add(digest_b0).unwrap();
    digest_list.add(digest_b1).unwrap();

    let (t_or_sess, t_or_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_or(t_or_pol, digest_list.clone())?;
    let expected_or_digest = client.policy_get_digest(t_or_pol)?;
    client.flush_session(t_or_sess)?;

    if expected_or_digest.value() != sw_expected_or.as_slice() {
        return Err(anyhow!(
            "TPM PolicyOR trial digest ({}) did not match software oracle ({})",
            hex::encode(expected_or_digest.value()),
            hex::encode(&sw_expected_or)
        ));
    }
    info!("PASS: TPM Trial Session digest matches software oracle");

    // 4. Create sealed data object bound to the verified policy digest with random secret bytes
    let mut rng = TestRandom::from_env();
    let secret = rng.random_bytes(32);
    let sealed_handle = client
        .create_and_load_sealed_data(srk_handle, expected_or_digest, None, &secret)
        .context("create/load sealed data")?;

    // 5. Authorize with Live Policy session using Branch 0 (Unseal + LocZero)
    let (live_sess, live_pol) = client.start_live_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(live_pol, CommandCode::Unseal)?;
    client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ZERO)?;
    client.policy_or(live_pol, digest_list.clone())?;

    // Verify live session digest before executing command
    let live_dig = client.policy_get_digest(live_pol)?;
    if live_dig.value() != sw_expected_or.as_slice() {
        return Err(anyhow!(
            "Live Policy session digest mismatch (PolicyGetDigest)"
        ));
    }
    info!("PASS: Live PolicyGetDigest matches expected software digest");

    let unsealed = client
        .unseal_with_session(sealed_handle.into(), live_sess)
        .context("unseal with Branch 0")?;

    if unsealed.value() != secret.as_slice() {
        return Err(anyhow!("Unsealed data mismatch"));
    }
    info!("PASS: Unsealed successfully with Branch 0");

    // 6. Test PolicyRestart and verify wrong locality is rejected by PolicyOR or execution
    client.policy_restart(live_pol).context("policy restart")?;
    client.policy_command_code(live_pol, CommandCode::Unseal)?;
    client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ONE)?; // Mismatched locality!
    let bad_or = client.policy_or(live_pol, digest_list);

    if bad_or.is_ok() {
        let bad_loc_res = client.unseal_with_session(sealed_handle.into(), live_sess);
        if bad_loc_res.is_ok() {
            return Err(anyhow!("FAIL: Unseal succeeded with mismatched locality"));
        }
    }
    info!("PASS: Policy correctly rejected when executed with bad locality");

    client.flush_context(sealed_handle.into())?;
    client.flush_context(srk_handle.into())?;
    client.flush_session(live_sess)?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Policy | Smoke",
    hierarchies = "Owner",
    description = "Verifies nested policy tree with multiple AND/OR branches"
)]
fn test_policy_3() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let srk_handle = client.create_rsa_srk_primary().context("create SRK")?;

    // 1. Compute Policy Tree in Software (matching TestPolicy3)
    let initial_zeros = [0u8; 32];

    // Branch 0: PolicyCommandCode(Unseal) -> PolicyLocality(LocZero)
    let sw_b0_step1 = sw_policy_command_code(&initial_zeros, CommandCode::Unseal);
    let sw_b0 = sw_policy_locality(&sw_b0_step1, LocalityAttributes::LOCALITY_ZERO);

    // Branch 1: PolicyLocality(LocThree) -> PolicyCommandCode(CreatePrimary)
    let sw_b1_step1 = sw_policy_locality(&initial_zeros, LocalityAttributes::LOCALITY_THREE);
    let sw_b1 = sw_policy_command_code(&sw_b1_step1, CommandCode::CreatePrimary);

    // Nested Branch 2: PolicyLocality(LocZero) -> PolicyOR(SetPrimaryPolicy, ClearControl)
    let sw_b2_prefix = sw_policy_locality(&initial_zeros, LocalityAttributes::LOCALITY_ZERO);
    let sw_b20 = sw_policy_command_code(&sw_b2_prefix, CommandCode::SetPrimaryPolicy);
    let sw_b21 = sw_policy_command_code(&sw_b2_prefix, CommandCode::ClearControl);
    let sw_sub_or = sw_policy_or(&[&sw_b20, &sw_b21]);

    // Root PolicyOR(Branch 0, Branch 1, Branch 2)
    let sw_root_or = sw_policy_or(&[&sw_b0, &sw_b1, &sw_sub_or]);
    let root_digest = Digest::try_from(sw_root_or).context("convert root digest")?;

    // 2. Create sealed data object with software-calculated policy digest and random secret bytes
    let mut rng = TestRandom::from_env();
    let secret = rng.random_bytes(32);
    let sealed_handle = client
        .create_and_load_sealed_data(srk_handle, root_digest, None, &secret)
        .context("create/load sealed data")?;

    // 3. Authorize using Live Policy session on Branch 0 (Unseal + LocZero + Root PolicyOR)
    let (live_sess, live_pol) = client.start_live_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(live_pol, CommandCode::Unseal)?;
    client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ZERO)?;

    let mut root_or_list = DigestList::new();
    root_or_list
        .add(Digest::try_from(sw_b0).unwrap())
        .map_err(|e| anyhow!("add b0: {e:?}"))?;
    root_or_list
        .add(Digest::try_from(sw_b1).unwrap())
        .map_err(|e| anyhow!("add b1: {e:?}"))?;
    root_or_list
        .add(Digest::try_from(sw_sub_or).unwrap())
        .map_err(|e| anyhow!("add sub_or: {e:?}"))?;
    client.policy_or(live_pol, root_or_list)?;

    // 4. Unseal and verify secret payload
    let unsealed = client
        .unseal_with_session(sealed_handle.into(), live_sess)
        .context("unseal with nested policy Branch 0")?;

    if unsealed.value() != secret.as_slice() {
        return Err(anyhow!("Unsealed data mismatch in nested policy tree"));
    }
    info!("PASS: Nested policy tree successfully evaluated and authorized unseal");

    client.flush_context(sealed_handle.into())?;
    client.flush_context(srk_handle.into())?;
    client.flush_session(live_sess)?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Policy | Nv | Smoke",
    hierarchies = "Owner",
    sim_only = true,
    description = "Verifies complex policy with PolicyCommandCode, PolicyPassword, PolicyNV, PolicyLocality, and PolicyOR"
)]
fn test_policy_5() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let srk_handle = client.create_rsa_srk_primary().context("create SRK")?;
    let mut rng = TestRandom::from_env();

    let tpm_cfg = client.get_tpm_config().context("get tpm config")?;
    let max_digest_size = tpm_cfg.max_digest_size;
    let random_sub_size = (rng.next_u64() % (max_digest_size as u64 - 1) + 1) as usize;
    let nv_sizes = [random_sub_size, max_digest_size, max_digest_size + 1];

    let base_nv_idx = 0x01500020u32;
    for (i, &size) in nv_sizes.iter().enumerate() {
        let _ = client.nv_undefine_space(
            Provision::Owner,
            NvIndexHandle::from(base_nv_idx + i as u32),
        );
        let nv_index = NvIndexTpmHandle::new(base_nv_idx + i as u32).context("convert NV index")?;
        let nv_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_auth_read(true)
            .with_auth_write(true)
            .build()
            .context("build NV attributes")?;

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_attributes)
            .with_data_area_size(size)
            .build()
            .context("build NV public")?;

        let nv_handle = client
            .nv_define_space(Provision::Owner, nv_public)
            .context("nv_define_space")?;

        let contents = rng.random_bytes(size);
        let write_buf = MaxNvBuffer::try_from(contents.clone()).context("convert write buffer")?;
        client
            .nv_write(NvAuth::Owner, nv_handle, write_buf, 0)
            .context("nv_write")?;

        let (_out_pub, nv_name) = client.nv_read_public(nv_handle).context("nv_read_public")?;

        // 2. Compute Policy Tree in Software (matching TestPolicy5: Unseal -> Password -> PolicyNV -> LocZero)
        let initial_zeros = [0u8; 32];

        let sw_b0_step1 = sw_policy_command_code(&initial_zeros, CommandCode::Unseal);
        let sw_b0_step2 = sw_policy_auth_value(&sw_b0_step1);
        let sw_b0_step3 = sw_policy_nv(&sw_b0_step2, nv_name.value(), &contents, 0, 0);
        let sw_b0 = sw_policy_locality(&sw_b0_step3, LocalityAttributes::LOCALITY_ZERO);

        // Branch 1: PolicyLocality(LocThree) -> PolicyCommandCode(Unseal)
        let sw_b1_step1 = sw_policy_locality(&initial_zeros, LocalityAttributes::LOCALITY_THREE);
        let sw_b1 = sw_policy_command_code(&sw_b1_step1, CommandCode::Unseal);

        // Root PolicyOR(Branch 0, Branch 1)
        let sw_root_or = sw_policy_or(&[&sw_b0, &sw_b1]);
        let root_digest = Digest::try_from(sw_root_or).context("convert root digest")?;

        // 3. Live session
        let (live_sess, live_pol) = client.start_live_policy_session(HashingAlgorithm::Sha256)?;

        // Test oversized operand: operand length exceeds NV index size
        let too_big_operand = rng.random_bytes(size + 1);
        client.policy_command_code(live_pol, CommandCode::Unseal)?;
        client.policy_password(live_pol)?;
        let too_big_res =
            client.policy_nv(NvAuth::Owner, nv_handle, live_pol, &too_big_operand, 0, 0);
        if size <= max_digest_size {
            assert!(
                too_big_res.is_err(),
                "Expected policy_nv to fail with oversized operand for size {size}"
            );
        }
        client.policy_restart(live_pol).context("policy restart")?;

        // Live execution: Check if policy_nv succeeds with actual contents
        client.policy_command_code(live_pol, CommandCode::Unseal)?;
        client.policy_password(live_pol)?;
        let pol_nv_res = client.policy_nv(NvAuth::Owner, nv_handle, live_pol, &contents, 0, 0);
        if pol_nv_res.is_err() && size > max_digest_size {
            // When operand size > max digest size, behavior is implementation dependent (may or may not fail)
            let _ = client.nv_undefine_space(Provision::Owner, nv_handle);
            let _ = client.flush_session(live_sess);
            continue;
        }
        pol_nv_res.context("policy_nv with valid contents")?;
        client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ZERO)?;

        let mut root_or_list = DigestList::new();
        root_or_list
            .add(Digest::try_from(sw_b0).unwrap())
            .map_err(|e| anyhow!("add b0: {e:?}"))?;
        root_or_list
            .add(Digest::try_from(sw_b1.clone()).unwrap())
            .map_err(|e| anyhow!("add b1: {e:?}"))?;
        client.policy_or(live_pol, root_or_list.clone())?;

        // 4. Create sealed data object with desired policy and object auth
        let secret = rng.random_bytes(32);
        let obj_auth = Auth::try_from(b"test_policy5_auth".to_vec()).unwrap();
        let sealed_handle = client
            .create_and_load_sealed_data(srk_handle, root_digest, Some(obj_auth.clone()), &secret)
            .context("create/load sealed data")?;

        // 5a. Negative check: Invalid auth value forced into session (must fail with TPM_RC_AUTH_FAIL)
        let wrong_auth = Auth::try_from(b"wrong_auth_value".to_vec()).unwrap();
        client.tr_set_auth(sealed_handle.into(), wrong_auth)?;
        let bad_auth_unseal = client.unseal_with_session(sealed_handle.into(), live_sess);
        ensure!(
            bad_auth_unseal.is_err(),
            "FAIL: Unseal succeeded with invalid object authValue (size={size})"
        );

        // 5b. Positive Unseal with valid auth and session
        client.tr_set_auth(sealed_handle.into(), obj_auth.clone())?;
        let unsealed = client
            .unseal_with_session(sealed_handle.into(), live_sess)
            .context("unseal with policy session and valid auth")?;

        if unsealed.value() != secret.as_slice() {
            return Err(anyhow!(
                "Unsealed data mismatch in test_policy_5 (size={size})"
            ));
        }
        info!(
            "PASS: PolicyNV (size={size}) + PolicyPassword + PolicyLocality unsealed successfully"
        );

        // 6a. Negative Check 1: Corrupt NV contents and verify PolicyNV with old operand fails
        client.policy_restart(live_pol).context("policy restart")?;
        let mut corrupted = contents.clone();
        corrupted[0] ^= 0xFF;
        let corrupted_buf =
            MaxNvBuffer::try_from(corrupted.clone()).context("convert corrupted buffer")?;
        client
            .nv_write(NvAuth::Owner, nv_handle, corrupted_buf, 0)
            .context("nv_write corrupted data")?;

        client.policy_command_code(live_pol, CommandCode::Unseal)?;
        client.policy_password(live_pol)?;
        let bad_pol_nv = client.policy_nv(NvAuth::Owner, nv_handle, live_pol, &contents, 0, 0);
        ensure!(
            bad_pol_nv.is_err(),
            "Expected policy_nv to fail when NV contents do not match OperandB (size={size})"
        );
        let bad_unseal = client.unseal_with_session(sealed_handle.into(), live_sess);
        ensure!(
            bad_unseal.is_err(),
            "FAIL: Unseal succeeded after NV contents were corrupted (size={size})"
        );

        // 6b. Negative Check 2: Update policy OperandB to match new NV contents; policy commands
        // succeed, but Unseal still fails because the resulting policy digest changed!
        client.policy_restart(live_pol).context("policy restart")?;
        let sw_corrupted_b0 = sw_policy_locality(
            &sw_policy_nv(&sw_b0_step2, nv_name.value(), &corrupted, 0, 0),
            LocalityAttributes::LOCALITY_ZERO,
        );
        let mut updated_or_list = DigestList::new();
        updated_or_list.add(Digest::try_from(sw_corrupted_b0)?)?;
        updated_or_list.add(Digest::try_from(sw_b1)?)?;

        client.policy_command_code(live_pol, CommandCode::Unseal)?;
        client.policy_password(live_pol)?;
        client.policy_nv(NvAuth::Owner, nv_handle, live_pol, &corrupted, 0, 0)?;
        client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ZERO)?;
        client.policy_or(live_pol, updated_or_list)?;

        let bad_digest_unseal = client.unseal_with_session(sealed_handle.into(), live_sess);
        ensure!(
            bad_digest_unseal.is_err(),
            "FAIL: Unseal succeeded with altered policy digest after NV update (size={size})"
        );
        info!("PASS: PolicyNV correctly rejected unseal after NV contents changed (size={size})");

        // Cleanup this iteration
        let _ = client.nv_undefine_space(Provision::Owner, nv_handle);
        client.flush_context(sealed_handle.into())?;
        client.flush_session(live_sess)?;
    }

    client.flush_context(srk_handle.into())?;
    Ok(())
}

/// Helper to print test vectors in standard format when regenerating test vectors.
#[allow(dead_code)]
fn write_test_val(name: &str, val: &str) {
    println!("{{\"{name}\", \"{val}\"}},");
}

/// Supporting routine for the NIAP trial policy test. Executes the trial policy
/// command on the TPM (if a trial runner is provided) and checks against the expected test vectors.
fn pp_check<F>(
    test: &str,
    client: &mut TpmClient,
    run_trial: Option<F>,
    expected_vectors: Option<&HashMap<&str, &str>>,
) -> Result<()>
where
    F: FnOnce(&mut TpmClient, PolicySession) -> Result<Digest>,
{
    let exp_hex = expected_vectors.and_then(|v| v.get(test).copied());

    let policy_digest = if let Some(runner) = run_trial {
        let (sess, pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
        let tpm_dig = runner(client, pol)?;
        client.flush_session(sess)?;
        tpm_dig.value().to_vec()
    } else if let Some(hex_str) = exp_hex {
        hex::decode(hex_str)?
    } else {
        return Err(anyhow!("No test vector and no trial runner for {test}"));
    };

    if let Some(exp_str) = exp_hex {
        let exp_bytes = hex::decode(exp_str)?;
        if policy_digest != exp_bytes.as_slice() {
            return Err(anyhow!(
                "[{test}] Test vector mismatch: expected {exp_str}, got {}",
                hex::encode(&policy_digest)
            ));
        }
    } else {
        write_test_val(test, &hex::encode(&policy_digest));
    }
    info!("PASS: {test} matched test vector");
    Ok(())
}

/// PPTestVectors contains the expected policy hashes after executing each named policy command
/// with the parameters specified in the preliminary/draft NIAP PP specification.
static PP_TEST_VECTORS: &[(&str, &str)] = &[
    ("PubKey", "9c12b95a8b6a585ce748eac3dfa0a409638f3c2dddcc72f8d1cfb7542a2d5cb0ad91d591806aff3e039f68553f7efd5956ae25ff17dfe5494a929344a6fc64a3b74f56731c279518ee61383159696e1cb16451671468b6086fb09a35b793dd1dcbae8e100c20d348238607236bf54bed096735db18fbdf8c1e718d7fcf5a4f05e686cb706336f6fe4dd288ad180c07662d8232fc61ddbe24b37a8d8ebee1bd69caa9a8ca945bf3ee5e7a3652026a4ff3730dbf6b11cab43603ba3f2b629ad6f9d74970b2bd06bfa56a833623b257563b0e1c45c05a1afbaed193e00b3ba91155c70f82cf2242addd640054c5568d0237a22bd181cf58a2a2d5228e27c6c72f23"),
    ("PrivKey", "c42de896c6698eb2cc6baf6ba4b94f9331ff3a6dfa0687fa532c75cd04c4c390176f0e058cb941147bc38857b0954708646ea2d1261dd7bf41d24f6a545b896522b9c372769deb7f57f4e9d2fa63c9e5e9660d072ec9e0a68053ebca5906065dc6ff5667fcaa5827544c27496232ee70c0da9e852c237dcd1b8e790862c09bcf"),
    ("PubKeyName", "000bb83c3d9a53ba3b9e95a9e97918640166160dcd42cf5ae5c699ca96c79b875197"),
    ("PCR16Val", "bba91ca85dc914b2ec3efb9e16e7267bf9193b14350d20fba8a8b406730ae30a"),
    ("PolicyPCR", "adc8bb37a36a2a2c5602349f08fd641c223691a9d15898cc279616c9aceae0ce"),
    ("PolicyLoc", "ddee6af14bf3c4e8127ced87bcf9a57e1c0c8ddb5e67735c8505f96f07b8dbb8"),
    ("PolicyCC", "bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2"),
    ("PolicyCp", "242c67f63c0b07e5e4d64e9306284ecc34f5229ad2aad22e6d6a4788a723afc6"),
    ("PolicyAuthVal", "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
    ("PolicyPwd", "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
    ("PolicyNameHash", "f0cfd1034841dc3d67004568e0311cd3689b77fabc28692ab192d4728637edd7"),
    ("PolicySecret", "2ea1ef612a7b31fdb6cefb6b76c595f83830d9b40442334facd9068595dc1579"),
    ("PolicyNvWritt", "f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb"),
    ("PolicyCTimer", "e28be805d0465ff78f3587a75cf72134b998b6152785a8901389bad5217b68db"),
    ("PolicyNv", "64d3c1b7dee3cc430de8fb57a71f8e387a70b6b6bdb6740bf46deb1e859f9cb4"),
    ("PolicySigned", "a9d473a0bac090303c6156dbfdd011bbe4ece5a686e7c2f81ae6d0dad8936b40"),
    ("PolicyAuthorize", "b50aabb89f349382f731bbba19ee9c816ec10390081043eec235790e3d71affd"),
    ("PolicyOr", "c8cf7c888787e6fd7ecee7e4fdecb40b6d1ee0970802188bd4be259b2bf77f1c"),
];

#[tpm_test(
    categories = "Compliance | Policy | Smoke",
    hierarchies = "Owner",
    sim_only = true,
    description = "Validates TPM trial policy commands against standard NIAP PP test vectors"
)]
fn test_niap_policy() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;
    let tpm_cfg = client.get_tpm_config().context("get tpm config")?;

    if !tpm_cfg.is_hash_supported(HashingAlgorithm::Sha256) {
        info!("SHA-256 not supported by TPM, skipping test_niap_policy");
        return Ok(());
    }

    let make_key = false;
    let expected_hashes: Option<HashMap<&str, &str>> = if make_key {
        None
    } else {
        Some(PP_TEST_VECTORS.iter().cloned().collect())
    };

    let zeros = [0u8; 32];

    // 1. PCR 16 Reset & Extend
    let pcr_slot = PcrSlot::Slot16;
    let pcr_sel_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[pcr_slot])
        .build()
        .context("build pcr selection")?;

    client.pcr_reset(pcr_slot).context("pcr reset 16")?;
    let ones = Digest::try_from(vec![0xFF; 32]).unwrap();
    let mut dig_values = DigestValues::new();
    dig_values.set(HashingAlgorithm::Sha256, ones);
    client
        .pcr_extend(pcr_slot, dig_values)
        .context("pcr extend 16")?;

    let (_, _, pcr_values) = client
        .pcr_read(pcr_sel_list.clone())
        .context("pcr read 16")?;
    let pcr_16_val = pcr_values.value()[0].value();

    if make_key {
        write_test_val("PCR16Val", &hex::encode(pcr_16_val));
    } else {
        let expected_pcr_16 = hex::decode(expected_hashes.as_ref().unwrap()["PCR16Val"])?;
        if pcr_16_val != expected_pcr_16.as_slice() {
            return Err(anyhow!(
                "PCR 16 value mismatch: expected {}, got {}",
                hex::encode(&expected_pcr_16),
                hex::encode(pcr_16_val)
            ));
        }
    }
    info!("PASS: PCR 16 reset and extend matched test vector");

    // 2. Define NV Index 0x01800000
    let nv_index_tpm = NvIndexTpmHandle::try_from(0x01800000u32).unwrap();
    let _ = client.nv_undefine_space(Provision::Owner, NvIndexHandle::from(0x01800000u32));

    let nv_attributes = NvIndexAttributesBuilder::new()
        .with_auth_read(true)
        .with_auth_write(true)
        .build()
        .unwrap();

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(nv_attributes)
        .with_data_area_size(4)
        .build()
        .unwrap();

    let nv_handle = client
        .nv_define_space(Provision::Owner, nv_public)
        .context("define NV index 0x01800000")?;
    client.nv_write(
        NvAuth::NvIndex(nv_handle),
        nv_handle,
        MaxNvBuffer::try_from(vec![0u8; 4]).unwrap(),
        0,
    )?;
    let (_, nv_name) = client.nv_read_public(nv_handle)?;
    let nv_name_hash = &nv_name.value()[2..];

    // --- Validate Trial Policy Commands via pp_check ---

    // PolicyPCR
    let pcr_composite = sw_hash(pcr_16_val, HashingAlgorithm::Sha256)?;
    let pcr_sel = pcr_sel_list.clone();
    pp_check(
        "PolicyPCR",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_pcr(pol, Digest::try_from(pcr_composite)?, pcr_sel)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyLoc
    let sw_loc = sw_policy_locality(&zeros, LocalityAttributes::LOCALITY_ZERO);
    let exp_loc = hex::decode(expected_hashes.as_ref().unwrap()["PolicyLoc"])?;
    if sw_loc.as_slice() != exp_loc.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyLoc"));
    }
    pp_check(
        "PolicyLoc",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_locality(pol, LocalityAttributes::LOCALITY_ZERO)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyCC
    let sw_cc = sw_policy_command_code(&zeros, CommandCode::Duplicate);
    let exp_cc = hex::decode(expected_hashes.as_ref().unwrap()["PolicyCC"])?;
    if sw_cc.as_slice() != exp_cc.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyCC"));
    }
    pp_check(
        "PolicyCC",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_command_code(pol, CommandCode::Duplicate)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyCp
    let mut get_random_cmd = Vec::new();
    get_random_cmd.extend_from_slice(&(CommandCode::GetRandom as u32).to_be_bytes());
    get_random_cmd.extend_from_slice(&32u16.to_be_bytes());
    let cp_hash = sw_hash(&get_random_cmd, HashingAlgorithm::Sha256)?;
    let sw_cp = sw_policy_cp_hash(&zeros, &cp_hash);
    let exp_cp = hex::decode(expected_hashes.as_ref().unwrap()["PolicyCp"])?;
    if sw_cp.as_slice() != exp_cp.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyCp"));
    }
    pp_check(
        "PolicyCp",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_cp_hash(pol, Digest::try_from(cp_hash)?)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyAuthVal
    let sw_auth = sw_policy_auth_value(&zeros);
    let exp_auth = hex::decode(expected_hashes.as_ref().unwrap()["PolicyAuthVal"])?;
    if sw_auth.as_slice() != exp_auth.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyAuthVal"));
    }
    pp_check(
        "PolicyAuthVal",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_auth_value(pol)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyPwd
    let sw_pwd = sw_policy_auth_value(&zeros);
    let exp_pwd = hex::decode(expected_hashes.as_ref().unwrap()["PolicyPwd"])?;
    if sw_pwd.as_slice() != exp_pwd.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyPwd"));
    }
    pp_check(
        "PolicyPwd",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_password(pol)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyNameHash
    let nv_name_hash_vec = nv_name_hash.to_vec();
    pp_check(
        "PolicyNameHash",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_name_hash(pol, Digest::try_from(nv_name_hash_vec)?)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicySecret
    pp_check(
        "PolicySecret",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_secret(
                pol,
                AuthHandle::from(nv_handle),
                Nonce::default(),
                Digest::default(),
                Nonce::default(),
                None,
            )?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyNvWritt
    pp_check(
        "PolicyNvWritt",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_nv_written(pol, true)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyCTimer
    let sw_ctimer = sw_policy_counter_timer(&zeros, &[0, 2, 1, 1], 0, 0);
    let exp_ctimer = hex::decode(expected_hashes.as_ref().unwrap()["PolicyCTimer"])?;
    if sw_ctimer.as_slice() != exp_ctimer.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyCounterTimer"));
    }
    pp_check(
        "PolicyCTimer",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_counter_timer(pol, &[0, 2, 1, 1], 0, 0)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyNv
    let sw_nv = sw_policy_nv(&zeros, nv_name.value(), &[0, 2, 1, 1], 0, 0);
    let exp_nv = hex::decode(expected_hashes.as_ref().unwrap()["PolicyNv"])?;
    if sw_nv.as_slice() != exp_nv.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyNv"));
    }
    pp_check(
        "PolicyNv",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_nv(
                NvAuth::NvIndex(nv_handle),
                nv_handle,
                pol,
                &[0, 2, 1, 1],
                0,
                0,
            )?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // Load PP RSA PublicKey via LoadExternal and verify PubKeyName matches
    let pp_pub_bytes = hex::decode(expected_hashes.as_ref().unwrap()["PubKey"])?;
    let in_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_restricted(true)
                .with_sign_encrypt(true)
                .with_user_with_auth(true)
                .build()?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(true)
                .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(pp_pub_bytes)?)
        .build()?;

    let h_key = client
        .context
        .load_external_public(in_pub, Hierarchy::Owner)
        .context("load_external_public PP RSA key")?;
    let (_, verif_key_name, _) = client
        .read_public(h_key)
        .context("read_public PP RSA key")?;

    let pub_key_name = hex::decode(expected_hashes.as_ref().unwrap()["PubKeyName"])?;
    ensure!(
        verif_key_name.value() == pub_key_name.as_slice(),
        "LoadExternal PubKeyName mismatch: expected {}, got {}",
        hex::encode(&pub_key_name),
        hex::encode(verif_key_name.value())
    );

    // PolicySigned (executed on TPM trial session + software oracle check)
    let sw_signed = sw_policy_signed(&zeros, &pub_key_name, None);
    let exp_signed = hex::decode(expected_hashes.as_ref().unwrap()["PolicySigned"])?;
    if sw_signed.as_slice() != exp_signed.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicySigned"));
    }
    let dummy_sig = Signature::RsaSsa(RsaSignature::create(
        HashingAlgorithm::Sha256,
        PublicKeyRsa::try_from(vec![0u8; 256])?,
    )?);
    pp_check(
        "PolicySigned",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_signed(
                pol,
                ObjectHandle::from(h_key),
                Nonce::default(),
                Digest::default(),
                Nonce::default(),
                0,
                dummy_sig,
            )?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;
    client.flush_context(h_key.into())?;

    // PolicyAuthorize (executed on TPM trial session + software oracle check)
    let sw_authz = sw_policy_authorize(&pub_key_name, None);
    let exp_authz = hex::decode(expected_hashes.as_ref().unwrap()["PolicyAuthorize"])?;
    if sw_authz.as_slice() != exp_authz.as_slice() {
        return Err(anyhow!("Software oracle mismatch for PolicyAuthorize"));
    }
    let dummy_ticket = VerifiedTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
        tag: TPM2_ST_VERIFIED,
        hierarchy: TPM2_RH_OWNER,
        digest: Default::default(),
    })?;
    pp_check(
        "PolicyAuthorize",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_authorize(
                pol,
                Digest::default(),
                Nonce::default(),
                &verif_key_name,
                dummy_ticket,
            )?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    // PolicyOr
    let (b2_sess, b2_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    let _ = client.policy_secret(
        b2_pol,
        AuthHandle::Endorsement,
        Nonce::default(),
        Digest::default(),
        Nonce::default(),
        None,
    )?;
    let b2_digest = client.policy_get_digest(b2_pol)?;
    client.flush_session(b2_sess)?;

    let b1_digest = Digest::try_from(hex::decode(
        expected_hashes.as_ref().unwrap()["PolicyAuthVal"],
    )?)?;
    let mut or_digests = DigestList::new();
    or_digests.add(b1_digest)?;
    or_digests.add(b2_digest)?;

    pp_check(
        "PolicyOr",
        &mut client,
        Some(|cli: &mut TpmClient, pol| {
            cli.policy_auth_value(pol)?;
            cli.policy_or(pol, or_digests)?;
            cli.policy_get_digest(pol)
        }),
        expected_hashes.as_ref(),
    )?;

    let _ = client.nv_undefine_space(Provision::Owner, nv_handle);
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Policy | Asym | Smoke",
    hierarchies = "Owner",
    description = "Verifies normalized compound policy with PolicyAuthorize, PolicySigned, RSA signature verification, and PolicyOR"
)]
fn test_normalized_policies() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let srk_handle = client.create_rsa_srk_primary().context("create SRK")?;

    // 1. Calculate approved policy: PolicyPassword + PolicyCommandCode(ChangeEps)
    let initial_zeros = [0u8; 32];
    let d0 = sw_policy_auth_value(&initial_zeros);
    let approved_policy = sw_policy_command_code(&d0, CommandCode::ChangeEps);

    // 2. Create RSA signing key under SRK
    let sig_key = client
        .create_rsa_signing_key(srk_handle)
        .context("create RSA signing key")?;
    let (_, key_name, _) = client
        .context
        .read_public(sig_key)
        .context("read public signing key")?;

    // 3. Sign approval: dataToSign = approved_policy || policy_ref
    let policy_ref = [0x42u8; 32];
    let hash_to_sign = sha256_concat(&[&approved_policy, &policy_ref]);

    let sig = client
        .sign(
            sig_key,
            Digest::try_from(hash_to_sign.clone())?,
            SignatureScheme::RsaSsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            None,
        )
        .context("sign approved policy")?;

    let ticket = client
        .verify_signature(sig_key, Digest::try_from(hash_to_sign)?, sig)
        .context("verify signature to get ticket")?;

    // 4. Calculate expected normalized policy in software:
    // Branch 1: PolicyPassword + PolicyLocality(LOCALITY_ZERO)
    let b1_step1 = sw_policy_auth_value(&initial_zeros);
    let b1 = sw_policy_locality(&b1_step1, LocalityAttributes::LOCALITY_ZERO);

    // Branch 2: PolicyPassword + PolicyCommandCode(ChangeEps), then PolicyAuthorize replaces digest
    let b2 = sw_policy_authorize(key_name.value(), Some(&policy_ref));

    // Root PolicyOR([b1, b2])
    let sw_root = sw_policy_or(&[&b1, &b2]);

    let mut digest_list = DigestList::new();
    digest_list.add(Digest::try_from(b1)?)?;
    digest_list.add(Digest::try_from(b2)?)?;

    // 5. Test Branch 1 in live policy session
    let (live_sess, live_pol) = client.start_live_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_password(live_pol)?;
    client.policy_locality(live_pol, LocalityAttributes::LOCALITY_ZERO)?;
    client.policy_or(live_pol, digest_list.clone())?;

    let live_dig1 = client.policy_get_digest(live_pol)?;
    if live_dig1.value() != sw_root.as_slice() {
        return Err(anyhow!("Branch 1 normalized policy digest mismatch"));
    }
    info!("PASS: Branch 1 of normalized policy evaluated successfully");

    // 6. Test Branch 2 in live policy session (after restart)
    client
        .policy_restart(live_pol)
        .context("restart policy session")?;
    client.policy_password(live_pol)?;
    client.policy_command_code(live_pol, CommandCode::ChangeEps)?;
    let pre_authz_dig = client.policy_get_digest(live_pol)?;
    if pre_authz_dig.value() != approved_policy.as_slice() {
        return Err(anyhow!(
            "Pre-authorize digest does not match approved policy"
        ));
    }
    client
        .policy_authorize(
            live_pol,
            Digest::try_from(approved_policy)?,
            Nonce::try_from(policy_ref.to_vec())?,
            &key_name,
            ticket,
        )
        .context("policy authorize")?;
    client.policy_or(live_pol, digest_list)?;

    let live_dig2 = client.policy_get_digest(live_pol)?;
    if live_dig2.value() != sw_root.as_slice() {
        return Err(anyhow!("Branch 2 normalized policy digest mismatch"));
    }
    info!("PASS: Branch 2 of normalized policy evaluated successfully");

    // 7. Part 2 of TestNormalizedPolicies: PolicySigned on a live session with policyRef = [1, 2, 3]
    client
        .policy_restart(live_pol)
        .context("restart policy session for PolicySigned")?;
    let signed_policy_ref = [1u8, 2, 3];
    // Per TCG Part 3 TPM2_PolicySigned (with includeNonceTpm=false, expiration=0, cpHashA=empty):
    // aHash = H(expiration || policyRef)
    let a_hash = sha256_concat(&[&0i32.to_be_bytes(), &signed_policy_ref]);
    let signed_sig = client
        .sign(
            sig_key,
            Digest::try_from(a_hash)?,
            SignatureScheme::RsaSsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            None,
        )
        .context("sign PolicySigned aHash")?;

    client
        .policy_signed(
            live_pol,
            ObjectHandle::from(sig_key),
            Nonce::default(),
            Digest::default(),
            Nonce::try_from(signed_policy_ref.to_vec())?,
            0,
            signed_sig,
        )
        .context("execute live PolicySigned")?;

    let sw_signed_expected = sw_policy_signed(&initial_zeros, key_name.value(), Some(&signed_policy_ref));
    let live_signed_dig = client.policy_get_digest(live_pol)?;
    ensure!(
        live_signed_dig.value() == sw_signed_expected.as_slice(),
        "Live PolicySigned digest mismatch: expected {}, got {}",
        hex::encode(&sw_signed_expected),
        hex::encode(live_signed_dig.value())
    );
    info!("PASS: Part 2 live PolicySigned with policyRef=[1, 2, 3] evaluated successfully");

    client.flush_session(live_sess)?;
    client.flush_context(sig_key.into())?;
    client.flush_context(srk_handle.into())?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Policy | Pcr | Session | Smoke",
    hierarchies = "Owner",
    description = "Verifies trial policy cannot authorize execution but computes independent digests"
)]
fn test_trial_policy() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let srk_handle = client.create_rsa_srk_primary().context("create SRK")?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
        .build()
        .context("build PCR selection")?;

    let target_pcr_digest = Digest::try_from(vec![0xAA; 32]).unwrap();

    // 1. Calculate PolicyPCR digest in a Trial session with target PCR digest
    let (trial_sess, trial_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_pcr(trial_pol, target_pcr_digest.clone(), pcr_selection.clone())?;
    let expected_digest = client.policy_get_digest(trial_pol)?;

    // 2. Create sealed object with random secret bytes
    let mut rng = TestRandom::from_env();
    let secret = rng.random_bytes(32);
    let sealed_handle = client
        .create_and_load_sealed_data(srk_handle, expected_digest.clone(), None, &secret)
        .context("create/load sealed data")?;

    // 3. Attempting to use the Trial session for actual command execution MUST fail (TPM_RC_ATTRIBUTES)
    let trial_exec_res = client.unseal_with_session(sealed_handle.into(), trial_sess);
    if trial_exec_res.is_ok() {
        return Err(anyhow!(
            "FAIL: Trial session unexpectedly authorized execution!"
        ));
    }
    info!("PASS: Trial session correctly rejected when used for live command authorization");

    // 4. Modify PCR 16 on live TPM
    let extend_val = Digest::try_from(vec![0xFF; 32]).unwrap();
    let mut digest_values = DigestValues::new();
    digest_values.set(HashingAlgorithm::Sha256, extend_val);
    client
        .pcr_extend(PcrSlot::Slot16.into(), digest_values)
        .context("pcr_extend slot 16")?;

    // 5. Restart trial session and recompute policy with target PCR digest
    client
        .policy_restart(trial_pol)
        .context("restart trial session")?;
    client.policy_pcr(trial_pol, target_pcr_digest, pcr_selection)?;
    let digest_after = client.policy_get_digest(trial_pol)?;

    // In a trial session, policy calculation reflects target input, NOT live TPM PCR state
    if digest_after != expected_digest {
        return Err(anyhow!("Trial policy digest changed unexpectedly"));
    }
    info!("PASS: Trial session digest calculation correctly independent of live PCR state");

    client.flush_session(trial_sess)?;
    client.flush_context(sealed_handle.into())?;
    client.flush_context(srk_handle.into())?;
    Ok(())
}

#[tpm_test(
    categories = "Compliance | Policy | Nv | Smoke",
    hierarchies = "Owner",
    sim_only = true,
    description = "Verifies NV space access controlled by compound PolicyOR, and authorization rejection when policy attributes are unset"
)]
fn test_nv_with_policy() -> Result<()> {
    let mut client = TpmClient::connect_from_env().context("connect client")?;
    client.startup_clear().context("startup clear")?;

    let nv_index_tpm = NvIndexTpmHandle::try_from(0x015003E8u32).unwrap();
    let _ = client.nv_undefine_space(Provision::Owner, NvIndexHandle::from(0x015003E8u32));

    // --- Independent Software Ground Truth Calculation ---
    let initial_zeros = [0u8; 32];
    let sw_write = sw_policy_command_code(&initial_zeros, CommandCode::NvWrite);
    let sw_read = sw_policy_command_code(&initial_zeros, CommandCode::NvRead);
    let sw_expected_nv_or = sw_policy_or(&[&sw_write, &sw_read]);

    // 1. Calculate Branch Write: PolicyCommandCode(NvWrite)
    let (tw_sess, tw_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(tw_pol, CommandCode::NvWrite)?;
    let digest_write = client.policy_get_digest(tw_pol)?;
    client.flush_session(tw_sess)?;
    if digest_write.value() != sw_write.as_slice() {
        return Err(anyhow!("NvWrite digest mismatch with software oracle"));
    }

    // 2. Calculate Branch Read: PolicyCommandCode(NvRead)
    let (tr_sess, tr_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(tr_pol, CommandCode::NvRead)?;
    let digest_read = client.policy_get_digest(tr_pol)?;
    client.flush_session(tr_sess)?;
    if digest_read.value() != sw_read.as_slice() {
        return Err(anyhow!("NvRead digest mismatch with software oracle"));
    }

    // 3. Calculate PolicyOR(NvWrite, NvRead)
    let mut digest_list = DigestList::new();
    digest_list.add(digest_write).unwrap();
    digest_list.add(digest_read).unwrap();

    let (tor_sess, tor_pol) = client.start_trial_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_or(tor_pol, digest_list.clone())?;
    let expected_nv_policy = client.policy_get_digest(tor_pol)?;
    client.flush_session(tor_sess)?;

    if expected_nv_policy.value() != sw_expected_nv_or.as_slice() {
        return Err(anyhow!("Nv PolicyOR digest mismatch with software oracle"));
    }

    // 4. Define NV Space with Policyread | Policywrite requiring expected_nv_policy
    let nv_attributes = NvIndexAttributesBuilder::new()
        .with_policy_write(true)
        .with_policy_read(true)
        .build()
        .unwrap();

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(nv_attributes)
        .with_index_auth_policy(expected_nv_policy.clone())
        .with_data_area_size(16)
        .build()
        .unwrap();

    let nv_handle = client
        .nv_define_space(Provision::Owner, nv_public)
        .context("nv_define_space with policy attrs")?;

    // 5. Authorize NvWrite using Live Policy session
    let (live_sess, live_pol) = client.start_live_policy_session(HashingAlgorithm::Sha256)?;
    client.policy_command_code(live_pol, CommandCode::NvWrite)?;
    client.policy_or(live_pol, digest_list.clone())?;

    let live_w_dig = client.policy_get_digest(live_pol)?;
    if live_w_dig.value() != sw_expected_nv_or.as_slice() {
        return Err(anyhow!("Live NvWrite policy digest mismatch"));
    }

    let write_data = MaxNvBuffer::try_from(vec![0x37; 16]).unwrap();
    client
        .context
        .execute_with_session(Some(live_sess), |ctx| {
            ctx.nv_write(NvAuth::NvIndex(nv_handle).into(), nv_handle, write_data, 0)
        })
        .context("nv_write with policy session")?;

    info!("PASS: NV write authorized successfully via PolicyOR NvWrite branch");

    // 6. Restart policy session and authorize NvRead using NvRead branch
    client.policy_restart(live_pol).context("policy restart")?;
    client.policy_command_code(live_pol, CommandCode::NvRead)?;
    client.policy_or(live_pol, digest_list.clone())?;

    let live_r_dig = client.policy_get_digest(live_pol)?;
    if live_r_dig.value() != sw_expected_nv_or.as_slice() {
        return Err(anyhow!("Live NvRead policy digest mismatch"));
    }

    let read_data = client
        .context
        .execute_with_session(Some(live_sess), |ctx| {
            ctx.nv_read(NvAuth::NvIndex(nv_handle).into(), nv_handle, 16, 0)
        })
        .context("nv_read with policy session")?;

    if read_data.value() != [0x37; 16] {
        return Err(anyhow!("NV read data mismatch"));
    }
    info!("PASS: NV read authorized successfully via PolicyOR NvRead branch");

    let _ = client.nv_undefine_space(Provision::Owner, nv_handle);

    // 7. Define NV Space with Authread | Authwrite (NO policy attributes)
    let auth_attributes = NvIndexAttributesBuilder::new()
        .with_auth_read(true)
        .with_auth_write(true)
        .build()
        .unwrap();

    let nv_auth_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(auth_attributes)
        .with_index_auth_policy(expected_nv_policy)
        .with_data_area_size(16)
        .build()
        .unwrap();

    let nv_auth_handle = client
        .nv_define_space(Provision::Owner, nv_auth_public)
        .context("nv_define_space with auth attrs")?;

    // 8. Attempting to write with policy session should be rejected
    client.policy_restart(live_pol).context("policy restart")?;
    client.policy_command_code(live_pol, CommandCode::NvWrite)?;
    client.policy_or(live_pol, digest_list.clone())?;
    let bad_write = client.context.execute_with_session(Some(live_sess), |ctx| {
        ctx.nv_write(
            NvAuth::NvIndex(nv_auth_handle).into(),
            nv_auth_handle,
            MaxNvBuffer::try_from(vec![0x37; 16]).unwrap(),
            0,
        )
    });
    if bad_write.is_ok() {
        return Err(anyhow!(
            "FAIL: nv_write unexpectedly succeeded without policywrite attribute"
        ));
    }
    info!("PASS: nv_write correctly rejected when policywrite attribute is unset");

    // 9. Attempting to read with policy session should be rejected
    client.policy_restart(live_pol).context("policy restart")?;
    client.policy_command_code(live_pol, CommandCode::NvRead)?;
    client.policy_or(live_pol, digest_list)?;
    let bad_read = client.context.execute_with_session(Some(live_sess), |ctx| {
        ctx.nv_read(
            NvAuth::NvIndex(nv_auth_handle).into(),
            nv_auth_handle,
            16,
            0,
        )
    });
    if bad_read.is_ok() {
        return Err(anyhow!(
            "FAIL: nv_read unexpectedly succeeded without policyread attribute"
        ));
    }
    info!("PASS: nv_read correctly rejected when policyread attribute is unset");

    client.flush_session(live_sess)?;
    let _ = client.nv_undefine_space(Provision::Owner, nv_auth_handle);
    Ok(())
}
