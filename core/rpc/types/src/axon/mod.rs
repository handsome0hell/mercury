pub mod generated;

use std::array::TryFromSliceError;

use ckb_types::{bytes::Bytes, packed, prelude::*, H160, H256};
use common::utils::to_fixed_array;
use serde::{Deserialize, Serialize};

use crate::TransactionCompletionResponse;
pub use molecule::error::VerificationError;

pub const AXON_CHECKPOINT_LOCK: &str = "axon_checkpoint";
pub const AXON_SELECTION_LOCK: &str = "axon_selection";
pub const AXON_STAKE_LOCK: &str = "axon_stake";
pub const AXON_WITHDRAW_LOCK: &str = "axon_withdraw";

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Identity {
    pub flag: u8,
    pub content: Bytes,
}

impl Identity {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.flag];
        let mut content = hex::decode(self.content.clone().split_off(2)).unwrap();
        res.append(&mut content);
        res
    }
}

impl TryFrom<Identity> for crate::Identity {
    type Error = String;

    fn try_from(id: Identity) -> Result<Self, Self::Error> {
        if id.content.len() != 42 {
            return Err(String::from("Invalid Admin Identity"));
        }

        let mut content =
            hex::decode(id.content.clone().split_off(2)).map_err(|e| e.to_string())?;
        let mut ret = vec![id.flag];
        ret.append(&mut content);
        Ok(Self(to_fixed_array(&ret)))
    }
}

impl TryFrom<Identity> for generated::Identity {
    type Error = String;

    fn try_from(id: Identity) -> Result<Self, Self::Error> {
        if id.content.len() != 42 {
            return Err(String::from("Invalid Admin Identity"));
        }

        let content = hex::decode(id.content.clone().split_off(2)).map_err(|e| e.to_string())?;

        Ok(generated::IdentityBuilder::default()
            .flag(packed::Byte::new(id.flag))
            .content(
                generated::Byte20Builder::default()
                    .set(to_packed_array::<20>(&content))
                    .build(),
            )
            .build())
    }
}

impl<'r> Into<Identity> for generated::IdentityReader<'r> {
    fn into(self) -> Identity {
        let flag = u8::from_le(self.flag().as_slice()[0]);
        let content = Bytes::copy_from_slice(self.content().as_slice());

        Identity { flag, content }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct OmniConfig {
    pub version: u8,
    pub max_supply: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct CheckpointConfig {
    pub version: u8,
    pub period_intervial: u32,
    pub era_period: u32,
    pub base_reward: String,
    pub half_period: u64,
    pub common_ref: Bytes,
    pub withdrawal_lock_hash: H256,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct StakeInfo {
    pub identity: Identity,
    pub l2_address: H160,
    pub bls_pub_key: Bytes,
    pub stake_amount: String,
    pub inauguration_era: u64,
}

impl<'a> TryInto<StakeInfo> for generated::StakeInfoReader<'a> {
    type Error = String;

    fn try_into(self) -> Result<StakeInfo, Self::Error> {
        let identity: Identity = self.identity().into();
        let inauguration_era = u64::from_le_bytes(
            self.inauguration_era()
                .as_slice()
                .try_into()
                .map_err(|err: TryFromSliceError| err.to_string())?,
        );

        let bls_pub_key = Bytes::copy_from_slice(self.bls_pub_key().as_slice());

        let stake_amount = u128::from_le_bytes(
            self.stake_amount()
                .as_slice()
                .try_into()
                .map_err(|err: TryFromSliceError| err.to_string())?,
        )
        .to_string();

        let l2_address = H160(
            <[u8; 20]>::try_from(self.l2_address().as_slice())
                .map_err(|err: TryFromSliceError| err.to_string())?,
        );

        Ok(StakeInfo {
            identity,
            inauguration_era,
            bls_pub_key,
            stake_amount,
            l2_address,
        })
    }
}

impl TryFrom<StakeInfo> for generated::StakeInfo {
    type Error = String;

    fn try_from(mut info: StakeInfo) -> Result<Self, Self::Error> {
        if info.bls_pub_key.len() != 196 {
            return Err(String::from("Invalid bls pubkey len"));
        }

        let stake_amount: u128 = info
            .stake_amount
            .clone()
            .parse()
            .map_err(|_| "stake_amount overflow".to_string())?;

        let bls_pub_key = hex::decode(&info.bls_pub_key.split_off(2)).unwrap();

        Ok(generated::StakeInfoBuilder::default()
            .identity(info.identity.try_into()?)
            .l2_address(info.l2_address.into())
            .bls_pub_key(
                generated::Byte97Builder::default()
                    .set(to_packed_array::<97>(&bls_pub_key))
                    .build(),
            )
            .stake_amount(pack_u128(stake_amount))
            .inauguration_era(pack_u64(info.inauguration_era))
            .build())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct StakeConfig {
    pub version: u8,
    pub stake_infos: Vec<StakeInfo>,
    pub quoram_size: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SidechainConfig {
    pub udt_hash: H256,
    pub omni_type_hash: H256,
    pub checkpoint_type_hash: H256,
    pub stake_type_hash: H256,
    pub selection_lock_hash: H256,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct InitChainPayload {
    pub omni_config: OmniConfig,
    pub check_point_config: CheckpointConfig,
    pub state_config: StakeConfig,
    pub admin_id: Identity,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InitChainResponse {
    pub tx: TransactionCompletionResponse,
    pub config: SidechainConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct IssueAssetPayload {
    pub admin_id: Identity,
    pub selection_lock_hash: H256,
    pub omni_type_hash: H256,
    pub receipt_address: Bytes,
    pub amount: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct CrossChainTransferPayload {
    pub sender: String,
    pub receiver: String,
    pub udt_hash: H256,
    pub amount: String,
    pub direction: u8,
    pub memo: H160,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SubmitCheckpointPayload {
    pub node_identity: Identity,
    pub period_number: u64,
    pub checkpoint: Bytes,
    pub selection_lock_args: Bytes,
    pub checkpoint_type_id_args: Bytes,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct UpdateStakePayload {
    pub fee_payer: Identity,
    pub stake_type_id_args: Bytes,
    pub new_quorum_size: Option<u8>,
    pub new_stake_infos: Option<Vec<StakeInfo>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct BurnWithdrawalPayload {
    pub change_address: String,
    pub checkpoint_type_id_args: Bytes,
    pub node_identity: Identity,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct UnlockWithdrawalPayload {
    pub change_address: String,
    pub checkpoint_type_id_args: Bytes,
    pub node_identity: Identity,
    pub receiver: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct UpdateCheckpointPayload {
    pub fee_payer: Identity,
    pub checkpoint_type_id_args: Bytes,
    pub new_state: Option<u8>,
    pub new_period: Option<u64>,
    pub new_era: Option<u64>,
    pub new_block_hash: Option<H256>,
    pub new_unlock_period: Option<u32>,
    pub new_common_ref: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct StakeTokenPayload {
    pub fee_payer: Identity,
    pub node_identity: Identity,
    pub checkpoint_type_id_args: Bytes,
    pub stake_type_id_args: Bytes,
    pub token_type_args: Bytes,
    pub amount: String,
}

pub fn to_packed_array<const LEN: usize>(input: &[u8]) -> [packed::Byte; LEN] {
    assert_eq!(input.len(), LEN);
    let mut list = [packed::Byte::new(0); LEN];
    for (idx, item) in list.iter_mut().enumerate() {
        *item = packed::Byte::new(input[idx]);
    }
    list
}

impl From<packed::Byte32> for generated::Byte32 {
    fn from(byte32: packed::Byte32) -> Self {
        generated::Byte32::new_unchecked(byte32.as_bytes())
    }
}

impl From<H160> for generated::Byte20 {
    fn from(h: H160) -> Self {
        generated::Byte20Builder::default()
            .set(to_packed_array::<20>(&h.0))
            .build()
    }
}

pub fn pack_u32(input: u32) -> generated::Byte4 {
    generated::Byte4Builder::default()
        .set(to_packed_array::<4>(&input.to_le_bytes()))
        .build()
}

pub fn pack_u64(input: u64) -> generated::Byte8 {
    generated::Byte8Builder::default()
        .set(to_packed_array::<8>(&input.to_le_bytes()))
        .build()
}

pub fn pack_u128(input: u128) -> generated::Byte16 {
    generated::Byte16Builder::default()
        .set(to_packed_array::<16>(&input.to_le_bytes()))
        .build()
}

pub fn unpack_byte16(input: generated::Byte16) -> u128 {
    let raw = input.raw_data().to_vec();
    u128::from_le_bytes(to_fixed_array(&raw))
}
