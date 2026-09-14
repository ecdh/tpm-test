pub extern crate anyhow;
pub extern crate enumflags2;
pub extern crate env_logger;
pub extern crate log;
pub extern crate tss_esapi;

pub mod metadata;
pub mod test_random;
pub mod tpm_config;
pub use enumflags2::{make_bitflags, BitFlags};
pub use metadata::{
    parse_category, parse_hierarchy, FilterArgs, FilterDecision, TestCaseMetadata, TestCategory,
    TestHierarchy,
};
pub use test_random::TestRandom;
pub use tpm_config::TpmConfig;
pub use tpm_test_macros::tpm_test;

use anyhow::{anyhow, Context as _, Result};
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::Signature as EcdsaSignature;
use log::info;
use num_traits::{FromPrimitive, ToPrimitive};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::EncodePublicKey as _;
#[allow(deprecated)]
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tss_esapi::abstraction::{
    ak::{create_ak_2, load_ak},
    ek::create_ek_public_from_default_template_2,
    AsymmetricAlgorithmSelection,
};
use tss_esapi::attributes::{
    LocalityAttributes, ObjectAttributesBuilder, SessionAttributesBuilder,
};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::constants::{CapabilityType, CommandCode, SessionType, StartupType};
use tss_esapi::handles::{
    AuthHandle, KeyHandle, NvIndexHandle, ObjectHandle, PcrHandle, PersistentTpmHandle, TpmHandle,
};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm, SymmetricMode,
};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve as TssEccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Attest, Auth, AuthTicket, CapabilityData, CreateKeyResult, CreatePrimaryKeyResult, Data,
    Digest, DigestList, DigestValues, EncryptedSecret, HashScheme, HashcheckTicket, IdObject,
    InitialValue, KeyedHashScheme, MaxBuffer, MaxNvBuffer, Name, Nonce, NvPublic,
    PcrSelectionList, PcrSlot, Private, Public, PublicBuilder, PublicKeyRsa,
    PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaScheme, SensitiveData, Signature,
    SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject, Timeout, VerifiedTicket,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Null,
}

impl TryFrom<HashAlg> for HashingAlgorithm {
    type Error = anyhow::Error;
    fn try_from(a: HashAlg) -> Result<Self, Self::Error> {
        match a {
            HashAlg::Sha1 => Ok(Self::Sha1),
            HashAlg::Sha256 => Ok(Self::Sha256),
            HashAlg::Sha384 => Ok(Self::Sha384),
            HashAlg::Sha512 => Ok(Self::Sha512),
            HashAlg::Sm3_256 => Ok(Self::Sm3_256),
            HashAlg::Sha3_256 => Ok(Self::Sha3_256),
            HashAlg::Sha3_384 => Ok(Self::Sha3_384),
            HashAlg::Sha3_512 => Ok(Self::Sha3_512),
            HashAlg::Null => Ok(Self::Null),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EccCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl TryFrom<EccCurve> for TssEccCurve {
    type Error = anyhow::Error;
    fn try_from(a: EccCurve) -> Result<Self, Self::Error> {
        match a {
            EccCurve::NistP192 => Ok(Self::NistP192),
            EccCurve::NistP224 => Ok(Self::NistP224),
            EccCurve::NistP256 => Ok(Self::NistP256),
            EccCurve::NistP384 => Ok(Self::NistP384),
            EccCurve::NistP521 => Ok(Self::NistP521),
            EccCurve::BnP256 => Ok(Self::BnP256),
            EccCurve::BnP638 => Ok(Self::BnP638),
            EccCurve::Sm2P256 => Ok(Self::Sm2P256),
        }
    }
}

pub struct TpmClient {
    pub context: Context,
}

impl TpmClient {
    /// Connect to the TPM using the TCTI configuration from the environment.
    /// This uses the TPM2TOOLS_TCTI environment variable.
    /// If the environment variable is not set, it defaults to "mssim".
    pub fn connect_from_env() -> Result<Self> {
        let tcti_conf = std::env::var("TPM2TOOLS_TCTI").unwrap_or_else(|_| "mssim".to_string());
        Self::connect_with_tcti(&tcti_conf)
    }

    /// Connect to the TPM using the provided TCTI configuration string.
    pub fn connect_with_tcti(tcti_conf: &str) -> Result<Self> {
        let tcti = TctiNameConf::from_str(tcti_conf).context("tcti parse")?;
        let context = Context::new(tcti).context("context new")?;
        Ok(Self { context })
    }

    pub fn connect(tpm_addr: SocketAddr, platform_addr: SocketAddr) -> Result<Self> {
        let conf = format!(
            "mssim:host={},port={},platform_port={}",
            tpm_addr.ip(),
            tpm_addr.port(),
            platform_addr.port()
        );
        Self::connect_with_tcti(&conf)
    }

    pub fn startup_clear(&mut self) -> Result<()> {
        self.context
            .startup(StartupType::Clear)
            .context("startup clear")?;
        Ok(())
    }

    pub fn shutdown_restart(&mut self) -> Result<()> {
        self.context
            .shutdown(StartupType::State)
            .context("shutdown state")?;
        self.context
            .startup(StartupType::State)
            .context("startup state")?;
        Ok(())
    }

    pub fn pcr_read(
        &mut self,
        selection: PcrSelectionList,
    ) -> Result<(u32, PcrSelectionList, DigestList)> {
        self.context.clear_sessions();
        self.context.pcr_read(selection).context("pcr_read")
    }

    pub fn pcr_extend(&mut self, slot: PcrSlot, digests: DigestValues) -> Result<()> {
        let pcr_index = slot.to_u32().unwrap().trailing_zeros();
        let handle = PcrHandle::from_u32(pcr_index).ok_or_else(|| anyhow!("invalid pcr index"))?;
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .pcr_extend(handle, digests)
            .context("pcr_extend");
        self.context.clear_sessions();
        res
    }

    pub fn pcr_reset(&mut self, slot: PcrSlot) -> Result<()> {
        let pcr_index = slot.to_u32().unwrap().trailing_zeros();
        let handle = PcrHandle::from_u32(pcr_index).ok_or_else(|| anyhow!("invalid pcr index"))?;
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self.context.pcr_reset(handle).context("pcr_reset");
        self.context.clear_sessions();
        res
    }

    pub fn create_primary(
        &mut self,
        hierarchy: Hierarchy,
        public: Public,
    ) -> Result<CreatePrimaryKeyResult> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .create_primary(hierarchy, public, None, None, None, None)
            .context("create_primary")?;
        self.context.clear_sessions();
        Ok(res)
    }

    pub fn create(&mut self, parent: KeyHandle, public: Public) -> Result<CreateKeyResult> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .create(parent, public, None, None, None, None)
            .context("create")?;
        self.context.clear_sessions();
        Ok(res)
    }

    pub fn load(
        &mut self,
        parent: KeyHandle,
        private: Private,
        public: Public,
    ) -> Result<KeyHandle> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self.context.load(parent, private, public).context("load")?;
        self.context.clear_sessions();
        Ok(res)
    }

    pub fn read_public(&mut self, handle: KeyHandle) -> Result<(Public, Name, Name)> {
        self.context.read_public(handle).context("read_public")
    }

    pub fn flush_context(&mut self, handle: ObjectHandle) -> Result<()> {
        self.context
            .flush_context(handle.into())
            .context("flush_context")
    }

    pub fn flush_session(&mut self, session: AuthSession) -> Result<()> {
        let handle = tss_esapi::handles::SessionHandle::from(session);
        self.context
            .flush_context(handle.into())
            .context("flush_session")?;
        Ok(())
    }

    pub fn evict_control(
        &mut self,
        hierarchy: Hierarchy,
        object_handle: ObjectHandle,
        persistent_handle: PersistentTpmHandle,
    ) -> Result<()> {
        let provision = match hierarchy {
            Hierarchy::Owner => Provision::Owner,
            Hierarchy::Platform => Provision::Platform,
            _ => return Err(anyhow!("invalid hierarchy for evict_control")),
        };
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let _ = self
            .context
            .evict_control(
                provision,
                object_handle,
                Persistent::Persistent(persistent_handle),
            )
            .context("evict_control")?;
        self.context.clear_sessions();
        Ok(())
    }

    pub fn tr_from_tpm_public(&mut self, tpm_handle: TpmHandle) -> Result<ObjectHandle> {
        self.context
            .tr_from_tpm_public(tpm_handle)
            .context("tr_from_tpm_public")
    }

    pub fn tr_get_name(&mut self, handle: ObjectHandle) -> Result<Name> {
        self.context.tr_get_name(handle).context("tr_get_name")
    }

    pub fn encrypt_decrypt_2(
        &mut self,
        key_handle: KeyHandle,
        decrypt: bool,
        mode: SymmetricMode,
        in_data: MaxBuffer,
        iv_in: InitialValue,
    ) -> Result<(MaxBuffer, InitialValue)> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .encrypt_decrypt_2(key_handle, decrypt, mode, in_data, iv_in)
            .context("encrypt_decrypt_2");
        self.context.clear_sessions();
        res
    }

    /// Interrogates the TPM capability table once in bulk, returning a set of all implemented standard command codes.
    pub fn get_implemented_commands(&mut self) -> Result<HashSet<CommandCode>> {
        self.context.clear_sessions();
        let mut commands = HashSet::new();
        let mut property = 0x0000011Fu32;
        loop {
            let (cap_data, more_data) =
                match self
                    .context
                    .get_capability(CapabilityType::Command, property, 32)
                {
                    Ok(res) => res,
                    Err(_) => {
                        // Reached end of supported standard command range
                        break;
                    }
                };
            if let CapabilityData::Commands(cmd_list) = cap_data {
                if cmd_list.is_empty() {
                    break;
                }
                for cca in cmd_list.iter() {
                    let cc_raw: u32 = cca.command_index() as u32;
                    if let Ok(cc) = CommandCode::try_from(cc_raw) {
                        commands.insert(cc);
                    }
                    property = cc_raw + 1;
                }
            } else {
                break;
            }
            if !more_data {
                break;
            }
        }
        Ok(commands)
    }

    /// Discovers TPM configuration and capabilities directly from the connected TPM.
    pub fn get_tpm_config(&mut self) -> Result<TpmConfig> {
        TpmConfig::discover(&mut self.context)
    }

    pub fn make_credential(
        &mut self,
        handle: KeyHandle,
        credential: Digest,
        object_name: Name,
    ) -> Result<(IdObject, EncryptedSecret)> {
        self.context
            .make_credential(handle, credential, object_name)
            .context("make_credential")
    }

    pub fn start_auth_session(
        &mut self,
        tpm_key: Option<KeyHandle>,
        bind: Option<ObjectHandle>,
        nonce: Option<Nonce>,
        session_type: SessionType,
        symmetric: SymmetricDefinition,
        auth_hash: HashingAlgorithm,
    ) -> Result<Option<AuthSession>> {
        self.context
            .start_auth_session(tpm_key, bind, nonce, session_type, symmetric, auth_hash)
            .context("start_auth_session")
    }

    pub fn policy_secret(
        &mut self,
        policy_session: PolicySession,
        auth_handle: AuthHandle,
        nonce_tpm: Nonce,
        cp_hash_a: Digest,
        policy_ref: Nonce,
        expiration: Option<Duration>,
    ) -> Result<(Timeout, AuthTicket)> {
        self.context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.policy_secret(
                    policy_session,
                    auth_handle,
                    nonce_tpm,
                    cp_hash_a,
                    policy_ref,
                    expiration,
                )
            })
            .context("policy_secret")
    }

    pub fn policy_auth_value(&mut self, policy_session: PolicySession) -> Result<()> {
        self.context
            .policy_auth_value(policy_session)
            .context("policy_auth_value")
    }

    pub fn policy_command_code(
        &mut self,
        policy_session: PolicySession,
        code: CommandCode,
    ) -> Result<()> {
        self.context
            .policy_command_code(policy_session, code)
            .context("policy_command_code")
    }

    pub fn policy_pcr(
        &mut self,
        policy_session: PolicySession,
        pcr_digest: Digest,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<()> {
        self.context
            .policy_pcr(policy_session, pcr_digest, pcr_selection_list)
            .context("policy_pcr")
    }

    pub fn policy_or(&mut self, policy_session: PolicySession, digests: DigestList) -> Result<()> {
        self.context
            .policy_or(policy_session, digests)
            .context("policy_or")
    }

    pub fn policy_get_digest(&mut self, policy_session: PolicySession) -> Result<Digest> {
        self.context
            .policy_get_digest(policy_session)
            .context("policy_get_digest")
    }

    pub fn policy_restart(&mut self, policy_session: PolicySession) -> Result<()> {
        self.context
            .policy_restart(policy_session)
            .context("policy_restart")
    }

    pub fn policy_authorize(
        &mut self,
        policy_session: PolicySession,
        approved_policy: Digest,
        policy_ref: Nonce,
        key_sign: &Name,
        check_ticket: VerifiedTicket,
    ) -> Result<()> {
        self.context
            .policy_authorize(
                policy_session,
                approved_policy,
                policy_ref,
                key_sign,
                check_ticket,
            )
            .context("policy_authorize")
    }

    pub fn sign(
        &mut self,
        key_handle: KeyHandle,
        digest: Digest,
        scheme: SignatureScheme,
        validation: Option<HashcheckTicket>,
    ) -> Result<Signature> {
        let val = match validation {
            Some(v) => v,
            None => {
                let raw = tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: TPM2_ST_HASHCHECK,
                    hierarchy: TPM2_RH_NULL,
                    digest: Default::default(),
                };
                HashcheckTicket::try_from(raw).context("null hashcheck ticket")?
            }
        };
        self.context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.sign(key_handle, digest, scheme, val)
            })
            .context("sign")
    }

    pub fn verify_signature(
        &mut self,
        key_handle: KeyHandle,
        digest: Digest,
        signature: Signature,
    ) -> Result<VerifiedTicket> {
        self.context
            .verify_signature(key_handle, digest, signature)
            .context("verify_signature")
    }

    pub fn create_rsa_signing_key(&mut self, parent: KeyHandle) -> Result<KeyHandle> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .context("build signing key attributes")?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .context("build signing key rsa params")?;

        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .context("build signing key public template")?;

        let create_res = self
            .create_sealed(parent, template, None, None)
            .context("create signing key")?;
        self.load(parent, create_res.out_private, create_res.out_public)
            .context("load signing key")
    }

    pub fn unseal(&mut self, item_handle: ObjectHandle) -> Result<SensitiveData> {
        self.context.unseal(item_handle).context("unseal")
    }

    pub fn create_rsa_srk_primary(&mut self) -> Result<KeyHandle> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .context("build SRK attributes")?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_restricted(true)
            .with_is_decryption_key(true)
            .with_is_signing_key(false)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_scheme(RsaScheme::Null)
            .build()
            .context("build SRK rsa params")?;

        let rsa_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .context("build SRK public template")?;

        let res = self
            .create_primary(Hierarchy::Owner, rsa_template)
            .context("create SRK primary")?;
        Ok(res.key_handle)
    }

    pub fn create_and_load_sealed_data(
        &mut self,
        parent: KeyHandle,
        auth_policy: Digest,
        auth_value: Option<Auth>,
        sensitive_data: &[u8],
    ) -> Result<KeyHandle> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(auth_value.is_some())
            .with_admin_with_policy(false)
            .build()
            .context("build keyed hash attributes")?;

        let keyed_hash_params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_auth_policy(auth_policy)
            .with_keyed_hash_parameters(keyed_hash_params)
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .context("build keyed hash public")?;

        let sensitive = SensitiveData::try_from(sensitive_data.to_vec())
            .map_err(|_| anyhow!("create sensitive data"))?;

        let create_res = self
            .create_sealed(parent, template, auth_value, Some(sensitive))
            .context("create_sealed")?;

        self.load(parent, create_res.out_private, create_res.out_public)
            .context("load sealed data")
    }

    pub fn create_sealed(
        &mut self,
        parent: KeyHandle,
        public: Public,
        auth_value: Option<Auth>,
        sensitive_data: Option<SensitiveData>,
    ) -> Result<CreateKeyResult> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .create(parent, public, auth_value, sensitive_data, None, None)
            .context("create_sealed")?;
        self.context.clear_sessions();
        Ok(res)
    }

    pub fn start_trial_policy_session(
        &mut self,
        hash_alg: HashingAlgorithm,
    ) -> Result<(AuthSession, PolicySession)> {
        let session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::Null,
                hash_alg,
            )?
            .ok_or_else(|| anyhow!("start trial session failed"))?;
        let policy = PolicySession::try_from(session)
            .map_err(|_| anyhow!("convert trial session to policy session"))?;
        Ok((session, policy))
    }

    pub fn start_live_policy_session(
        &mut self,
        hash_alg: HashingAlgorithm,
    ) -> Result<(AuthSession, PolicySession)> {
        let session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::Null,
                hash_alg,
            )?
            .ok_or_else(|| anyhow!("start live policy session failed"))?;
        let policy = PolicySession::try_from(session)
            .map_err(|_| anyhow!("convert live session to policy session"))?;
        Ok((session, policy))
    }

    pub fn policy_password(&mut self, policy_session: PolicySession) -> Result<()> {
        self.context
            .policy_password(policy_session)
            .context("policy_password")
    }

    pub fn policy_locality(
        &mut self,
        policy_session: PolicySession,
        locality: LocalityAttributes,
    ) -> Result<()> {
        self.context
            .policy_locality(policy_session, locality)
            .context("policy_locality")
    }

    pub fn policy_cp_hash(&mut self, policy_session: PolicySession, cp_hash: Digest) -> Result<()> {
        self.context
            .policy_cp_hash(policy_session, cp_hash)
            .context("policy_cp_hash")
    }

    pub fn policy_name_hash(
        &mut self,
        policy_session: PolicySession,
        name_hash: Digest,
    ) -> Result<()> {
        self.context
            .policy_name_hash(policy_session, name_hash)
            .context("policy_name_hash")
    }

    pub fn policy_physical_presence(&mut self, policy_session: PolicySession) -> Result<()> {
        self.context
            .policy_physical_presence(policy_session)
            .context("policy_physical_presence")
    }

    pub fn policy_nv_written(
        &mut self,
        policy_session: PolicySession,
        written_set: bool,
    ) -> Result<()> {
        self.context
            .policy_nv_written(policy_session, written_set)
            .context("policy_nv_written")
    }

    pub fn tr_set_auth(&mut self, object_handle: ObjectHandle, auth: Auth) -> Result<()> {
        self.context
            .tr_set_auth(object_handle, auth)
            .context("tr_set_auth")
    }

    pub fn unseal_with_session(
        &mut self,
        item_handle: ObjectHandle,
        session: AuthSession,
    ) -> Result<SensitiveData> {
        let res = self
            .context
            .execute_with_session(Some(session), |ctx| ctx.unseal(item_handle))
            .context("unseal_with_session");
        self.context.clear_sessions();
        res
    }

    pub fn unseal_with_sessions(
        &mut self,
        item_handle: ObjectHandle,
        sessions: (
            Option<AuthSession>,
            Option<AuthSession>,
            Option<AuthSession>,
        ),
    ) -> Result<SensitiveData> {
        let res = self
            .context
            .execute_with_sessions(sessions, |ctx| ctx.unseal(item_handle))
            .context("unseal_with_sessions");
        self.context.clear_sessions();
        res
    }

    pub fn activate_credential(
        &mut self,
        activate_handle: KeyHandle,
        key_handle: KeyHandle,
        id_object: IdObject,
        encrypted_secret: EncryptedSecret,
    ) -> Result<Digest> {
        self.context
            .activate_credential(activate_handle, key_handle, id_object, encrypted_secret)
            .context("activate_credential")
    }

    pub fn quote(
        &mut self,
        handle: KeyHandle,
        data: Data,
        scheme: SignatureScheme,
        selection: PcrSelectionList,
    ) -> Result<(Attest, Signature)> {
        self.context
            .quote(handle, data, scheme, selection)
            .context("quote")
    }

    pub fn nv_define_space(
        &mut self,
        hierarchy: Provision,
        public: NvPublic,
    ) -> Result<NvIndexHandle> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .nv_define_space(hierarchy, None, public)
            .context("nv_define_space");
        self.context.clear_sessions();
        res
    }

    pub fn nv_undefine_space(
        &mut self,
        hierarchy: Provision,
        nv_index: NvIndexHandle,
    ) -> Result<()> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .nv_undefine_space(hierarchy, nv_index)
            .context("nv_undefine_space");
        self.context.clear_sessions();
        res
    }

    pub fn nv_write(
        &mut self,
        auth_handle: NvAuth,
        nv_index: NvIndexHandle,
        data: MaxNvBuffer,
        offset: u16,
    ) -> Result<()> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .nv_write(auth_handle, nv_index, data, offset)
            .context("nv_write");
        self.context.clear_sessions();
        res
    }

    pub fn nv_read(
        &mut self,
        auth_handle: NvAuth,
        nv_index: NvIndexHandle,
        size: u16,
        offset: u16,
    ) -> Result<MaxNvBuffer> {
        self.context
            .set_sessions((Some(AuthSession::Password), None, None));
        let res = self
            .context
            .nv_read(auth_handle, nv_index, size, offset)
            .context("nv_read");
        self.context.clear_sessions();
        res
    }

    pub fn nv_read_public(&mut self, nv_index: NvIndexHandle) -> Result<(NvPublic, Name)> {
        self.context
            .nv_read_public(nv_index)
            .context("nv_read_public")
    }

    pub fn create_ek(
        &mut self,
        alg: AsymmetricAlgorithmSelection,
    ) -> Result<CreatePrimaryKeyResult> {
        let pubtmpl =
            create_ek_public_from_default_template_2(alg, None).context("create ek template")?;
        self.create_primary(Hierarchy::Endorsement, pubtmpl)
    }

    pub fn setup_ak(
        &mut self,
        ek_handle: KeyHandle,
        hash_alg: HashingAlgorithm,
        key_alg: AsymmetricAlgorithmSelection,
        sign_alg: SignatureSchemeAlgorithm,
    ) -> Result<(KeyHandle, Public)> {
        let ak_res = create_ak_2(
            &mut self.context,
            ek_handle,
            hash_alg,
            key_alg,
            sign_alg,
            None,
            None,
        )
        .context("create ak")?;

        let ak_handle = load_ak(
            &mut self.context,
            ek_handle,
            None,
            ak_res.out_private,
            ak_res.out_public.clone(),
        )
        .context("load ak")?;

        self.activate_credential_flow(ek_handle, ak_handle)
            .context("activate ak credential")?;

        Ok((ak_handle, ak_res.out_public))
    }

    pub fn activate_credential_flow(
        &mut self,
        ek_handle: KeyHandle,
        ak_handle: KeyHandle,
    ) -> Result<()> {
        let (ek_public, _, _) = self.read_public(ek_handle)?;
        let hash_alg = ek_public.name_hashing_algorithm();
        let sym = ek_public
            .symmetric_algorithm()
            .expect("symmetric algorithm");

        let ak_name = self.tr_get_name(ObjectHandle::from(ak_handle))?;
        let secret_data = b"my secret word";
        let credential = Digest::try_from(secret_data.to_vec())?;

        let (id_object, encrypted_secret) = self
            .make_credential(ek_handle, credential, ak_name)
            .context("make_credential")?;

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

        let session_1 = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| anyhow!("failed to start hmac session"))?;

        self.context
            .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
            .context("set session 1 attributes")?;

        let policy_session = self
            .start_auth_session(None, None, None, SessionType::Policy, sym.into(), hash_alg)?
            .ok_or_else(|| anyhow!("failed to start policy session"))?;

        self.context
            .tr_sess_set_attributes(policy_session, session_attributes, session_attributes_mask)
            .context("set policy session attributes")?;

        self.context
            .execute_with_session(Some(session_1), |ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(policy_session).expect("convert to policy session"),
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                )
            })
            .context("policy_secret")?;

        let decrypted_credential = self
            .context
            .execute_with_sessions((Some(session_1), Some(policy_session), None), |ctx| {
                ctx.activate_credential(ak_handle, ek_handle, id_object, encrypted_secret)
            })
            .context("activate_credential")?;

        if decrypted_credential.value() != secret_data {
            return Err(anyhow!("decrypted credential mismatch"));
        }

        Ok(())
    }

    pub fn get_random(&mut self, n: usize) -> Result<Vec<u8>> {
        let res = self.context.get_random(n).context("get_random")?;
        Ok(res.value().to_vec())
    }

    pub fn hash(&mut self, data: &[u8], hash_alg: HashingAlgorithm) -> Result<Digest> {
        let (digest, _ticket) = self
            .context
            .hash(
                data.try_into()
                    .context("Data too large for single hash command")?,
                hash_alg,
                Hierarchy::Owner,
            )
            .context("hash")?;
        Ok(digest)
    }

    pub fn execute_with_nullauth_session<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Context) -> Result<R>,
    {
        self.context.execute_with_nullauth_session(f)
    }
}

pub fn print_key(name: &str, tpm_name: &Name, public: &Public) -> Result<()> {
    info!("{name}   = {}", hex::encode(tpm_name.value()));
    match public {
        Public::Ecc { unique, .. } => {
            info!("{name}.x = {}", hex::encode(unique.x().value()));
            info!("{name}.y = {}", hex::encode(unique.y().value()));
            Ok(())
        }
        Public::Rsa {
            parameters, unique, ..
        } => {
            info!("{name}.exponent = {:x}", parameters.exponent().value());
            info!("{name}.modulus = {}", hex::encode(unique.value()));
            Ok(())
        }
        _ => Err(anyhow!("Don't know how to print {public:x?}")),
    }
}

#[allow(deprecated)]
pub fn save_key(filename: &str, public: &Public) -> Result<()> {
    match public {
        Public::Ecc { unique, .. } => {
            let x_bytes: [u8; 32] = <[u8; 32]>::try_from(unique.x().value()).map_err(|_| {
                anyhow!("Unsupported ECC curve: x coordinate length is not 32 bytes")
            })?;
            let y_bytes: [u8; 32] = <[u8; 32]>::try_from(unique.y().value()).map_err(|_| {
                anyhow!("Unsupported ECC curve: y coordinate length is not 32 bytes")
            })?;
            let key =
                VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                    &GenericArray::from(x_bytes),
                    &GenericArray::from(y_bytes),
                    false,
                ))
                .context("Failed to create verifying key from raw public key")?;
            key.write_public_key_der_file(filename)
                .context("Saving public key")?;
            Ok(())
        }
        Public::Rsa {
            parameters, unique, ..
        } => {
            let mut exponent = parameters.exponent().value();
            if exponent == 0 {
                exponent = 0x10001;
            }
            let key = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(unique.value()),
                rsa::BigUint::from_bytes_be(&exponent.to_be_bytes()),
            )
            .context("Failed to create rsa public key from raw public key")?;
            key.write_public_key_der_file(filename)
                .context("Saving public key")?;
            Ok(())
        }

        _ => Err(anyhow!("Don't know how to save {public:x?}")),
    }
}

#[allow(deprecated)]
pub fn public_verify(public: &Public, signature: &Signature, digest: &[u8]) -> Result<bool> {
    match public {
        Public::Ecc { unique, .. } => {
            let x_bytes: [u8; 32] = <[u8; 32]>::try_from(unique.x().value()).map_err(|_| {
                anyhow!("Unsupported ECC curve: x coordinate length is not 32 bytes")
            })?;
            let y_bytes: [u8; 32] = <[u8; 32]>::try_from(unique.y().value()).map_err(|_| {
                anyhow!("Unsupported ECC curve: y coordinate length is not 32 bytes")
            })?;
            let key =
                VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                    &GenericArray::from(x_bytes),
                    &GenericArray::from(y_bytes),
                    false,
                ))
                .context("Failed to create verifying key from raw public key")?;
            let Signature::EcDsa(s) = signature else {
                return Err(anyhow!("Unexpected signature {signature:x?}"));
            };
            let mut raw = s.signature_r().value().to_vec();
            raw.extend(s.signature_s().value());
            let sig = EcdsaSignature::from_slice(&raw).context("convert signature")?;
            match key.verify_prehash(digest, &sig) {
                Ok(()) => Ok(true),
                Err(e) => Err(anyhow!("ecc verify failed: {e}")),
            }
        }
        Public::Rsa {
            parameters, unique, ..
        } => {
            let mut exponent = parameters.exponent().value();
            if exponent == 0 {
                exponent = 0x10001;
            }
            let key = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(unique.value()),
                rsa::BigUint::from_bytes_be(&exponent.to_be_bytes()),
            )
            .context("Failed to create rsa public key from raw public key")?;
            let result = match signature {
                Signature::RsaSsa(s) => match s.hashing_algorithm() {
                    HashingAlgorithm::Sha256 => key.verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        digest,
                        s.signature().value(),
                    ),
                    HashingAlgorithm::Sha384 => key.verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        digest,
                        s.signature().value(),
                    ),
                    HashingAlgorithm::Sha512 => key.verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        digest,
                        s.signature().value(),
                    ),
                    other => {
                        return Err(anyhow!(
                            "Unsupported hash algorithm for RSA-SSA: {:?}",
                            other
                        ))
                    }
                },
                Signature::RsaPss(s) => match s.hashing_algorithm() {
                    HashingAlgorithm::Sha256 => key.verify(
                        rsa::pss::Pss::new::<sha2::Sha256>(),
                        digest,
                        s.signature().value(),
                    ),
                    HashingAlgorithm::Sha384 => key.verify(
                        rsa::pss::Pss::new::<sha2::Sha384>(),
                        digest,
                        s.signature().value(),
                    ),
                    HashingAlgorithm::Sha512 => key.verify(
                        rsa::pss::Pss::new::<sha2::Sha512>(),
                        digest,
                        s.signature().value(),
                    ),
                    other => {
                        return Err(anyhow!(
                            "Unsupported hash algorithm for RSA-PSS: {:?}",
                            other
                        ))
                    }
                },
                _ => {
                    return Err(anyhow!("Unexpected signature {signature:x?}"));
                }
            };
            match result {
                Ok(()) => Ok(true),
                Err(e) => Err(anyhow!("rsa verify failed: {e}")),
            }
        }
        _ => Err(anyhow!(
            "Don't know how to create a verifying key from {public:x?}"
        )),
    }
}

pub fn print_signature(signature: &Signature) -> Result<()> {
    match signature {
        Signature::EcDsa(s) => {
            info!("ecc.hashalg = {:?}", s.hashing_algorithm());
            info!("ecc.r = {}", hex::encode(s.signature_r().value()));
            info!("ecc.s = {}", hex::encode(s.signature_s().value()));
            Ok(())
        }
        Signature::RsaSsa(s) => {
            info!("rsa.hashalg = {:?}", s.hashing_algorithm());
            info!("rsa.ssa_sig = {}", hex::encode(s.signature().value()));
            Ok(())
        }
        Signature::RsaPss(s) => {
            info!("rsa.hashalg = {:?}", s.hashing_algorithm());
            info!("rsa.pss_sig = {}", hex::encode(s.signature().value()));
            Ok(())
        }

        _ => Err(anyhow!("Don't know how to print {signature:x?}")),
    }
}

pub fn save_signature(filename: &str, signature: &Signature) -> Result<()> {
    match signature {
        Signature::EcDsa(s) => {
            let mut r = s.signature_r().value().to_vec();
            r.extend(s.signature_s().value());
            std::fs::write(filename, &r)?;
            Ok(())
        }
        Signature::RsaSsa(s) => {
            std::fs::write(filename, s.signature().value())?;
            Ok(())
        }
        Signature::RsaPss(s) => {
            std::fs::write(filename, s.signature().value())?;
            Ok(())
        }
        _ => Err(anyhow!("Don't know how to save {signature:x?}")),
    }
}

pub fn sw_hash(data: &[u8], alg: HashingAlgorithm) -> Result<Vec<u8>> {
    match alg {
        HashingAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashingAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashingAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(anyhow!("Unsupported software hash algorithm: {:?}", alg)),
    }
}

fn env_flag_enabled(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false)
}

pub fn is_hardware_env() -> bool {
    env_flag_enabled("TPM_IS_HARDWARE")
}

pub fn is_dry_run_env() -> bool {
    env_flag_enabled("DRY_RUN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sw_hash() {
        let data = b"hello world";

        let sha256 = sw_hash(data, HashingAlgorithm::Sha256).unwrap();
        assert_eq!(
            hex::encode(sha256),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let sha384 = sw_hash(data, HashingAlgorithm::Sha384).unwrap();
        assert_eq!(
            hex::encode(sha384),
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
        );

        let sha512 = sw_hash(data, HashingAlgorithm::Sha512).unwrap();
        assert_eq!(
            hex::encode(sha512),
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
        );

        assert!(sw_hash(data, HashingAlgorithm::Sha1).is_err());
    }

    #[test]
    fn test_is_hardware_env() {
        std::env::remove_var("TPM_IS_HARDWARE");
        assert!(!is_hardware_env());

        for truthy in ["true", "TRUE", "1", " true "] {
            std::env::set_var("TPM_IS_HARDWARE", truthy);
            assert!(is_hardware_env(), "expected true for {:?}", truthy);
        }

        for falsy in ["false", "FALSE", "0", "", "no"] {
            std::env::set_var("TPM_IS_HARDWARE", falsy);
            assert!(!is_hardware_env(), "expected false for {:?}", falsy);
        }

        std::env::remove_var("TPM_IS_HARDWARE");
    }

    #[test]
    fn test_is_dry_run_env() {
        std::env::remove_var("DRY_RUN");
        assert!(!is_dry_run_env());

        for truthy in ["true", "TRUE", "1", " 1 "] {
            std::env::set_var("DRY_RUN", truthy);
            assert!(is_dry_run_env(), "expected true for {:?}", truthy);
        }

        for falsy in ["false", "FALSE", "0", "", "no"] {
            std::env::set_var("DRY_RUN", falsy);
            assert!(!is_dry_run_env(), "expected false for {:?}", falsy);
        }

        std::env::remove_var("DRY_RUN");
    }
}
