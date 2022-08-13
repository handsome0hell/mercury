use crate::r#impl::MercuryRpcImpl;
use crate::r#impl::build_tx::build_witnesses;
use crate::{error::CoreError, InnerResult};

use ckb_types::prelude::*;
use ckb_types::{bytes::Bytes, packed};

use ckb_types::core::{Capacity, TransactionView, FeeRate};
use ckb_sdk::tx_builder::{
    balance_tx_capacity, CapacityProvider, CapacityBalancer,
};
use common::utils::{decode_udt_amount, parse_address, to_fixed_array};
use common::{Context, ACP, SECP256K1, SUDT, PaginationRequest};
use core_ckb_client::CkbRpc;
use core_rpc_types::axon::{
    generated, unpack_byte16, CrossChainTransferPayload, InitChainPayload, IssueAssetPayload,
    SubmitCheckpointPayload, AXON_CHECKPOINT_LOCK, AXON_SELECTION_LOCK, AXON_STAKE_LOCK,
    AXON_WITHDRAW_LOCK,
};
use core_rpc_types::consts::{BYTE_SHANNONS, OMNI_SCRIPT, DEFAULT_FEE_RATE};
use core_rpc_types::TransactionCompletionResponse;

use std::collections::{HashMap, HashSet};

impl<C: CkbRpc> MercuryRpcImpl<C> {
    pub(crate) async fn prebuild_submit_tx(
        &self,
        ctx: Context,
        payload: SubmitCheckpointPayload,
    ) -> InnerResult<TransactionCompletionResponse> {
        let input_selection_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![payload.selection_lock_hash.clone()],
                vec![],
                None,
                None,
                PaginationRequest::default().limit(Some(1)),
            )
            .await?
            .response
            .first()
            .cloned()
            .ok_or_else(|| CoreError::CannotFindCell(AXON_SELECTION_LOCK.to_string()))?;

        let input_checkpoint_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![],
                vec![payload.checkpoint_type_hash.clone()],
                None,
                None,
                PaginationRequest::default().limit(Some(1)),
            )
            .await?
            .response
            .first()
            .cloned()
            .ok_or_else(|| CoreError::CannotFindCell(AXON_SELECTION_LOCK.to_string()))?;
        let base_reward = unpack_byte16(
            generated::CheckpointLockCellData::new_unchecked(
                input_checkpoint_cell.cell_data.clone(),
            )
            .base_reward(),
        );
        let sudt_args = input_selection_cell.cell_output.lock().calc_script_hash();
        let withdraw_cell = self.build_withdraw_cell(
            sudt_args.unpack(),
            payload.admin_id.clone(),
            payload.checkpoint_type_hash.pack(),
            payload.node_id.clone(),
        );

        let withdraw_cells = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![withdraw_cell.lock().calc_script_hash().unpack()],
                vec![withdraw_cell
                    .type_()
                    .to_opt()
                    .unwrap()
                    .calc_script_hash()
                    .unpack()],
                None,
                None,
                Default::default(),
            )
            .await?
            .response;

        let input_withdraw_cell = if withdraw_cells.len() < 2 {
            None
        } else {
            Some(
                withdraw_cells
                    .iter()
                    .max_by(|x, y| {
                        let res = x.block_number.cmp(&y.block_number);
                        if res.is_eq() {
                            return res;
                        }
                        let a: u32 = x.out_point.index().unpack();
                        let b: u32 = y.out_point.index().unpack();
                        a.cmp(&b)
                    })
                    .cloned()
                    .unwrap(),
            )
        };

        let output_selection_cell = input_selection_cell.clone();
        let output_checkpoint_cell = input_checkpoint_cell.clone();

        let (output_withdraw_cell, output_withdraw_data) =
            if let Some(cell) = input_withdraw_cell.clone() {
                let new_amount = decode_udt_amount(cell.cell_data.as_ref()).unwrap().checked_add(base_reward).unwrap();
                let mut data = new_amount.to_le_bytes().to_vec();
                data.extend_from_slice(&payload.period_number.to_le_bytes());
                (cell.cell_output.clone(), Bytes::from(data))
            } else {
                let mut data = base_reward.to_le_bytes().to_vec();
                data.extend_from_slice(&payload.period_number.to_le_bytes());
                (withdraw_cell, data.into())
            };

        let cell_deps = self.axon_submit_tx_cell_deps.get_or_init(||
            self
                .build_cell_deps(&[
                    AXON_STAKE_LOCK,
                    AXON_SELECTION_LOCK,
                    SUDT,
                    AXON_CHECKPOINT_LOCK,
                    AXON_WITHDRAW_LOCK,
                    SECP256K1,
                ])
                .expect("Failed to init axon submit tx cell deps")
        ).clone();

        let mut inputs = vec![input_selection_cell, input_checkpoint_cell];

        if let Some(cell) = input_withdraw_cell {
            inputs.push(cell.clone());
        }

        let tx_view = TransactionView::new_advanced_builder()
            .set_inputs(
                self.build_transfer_tx_cell_inputs(
                    &inputs,
                    None,
                    HashMap::default(),
                )?,
            )
            .set_outputs(vec![
                output_selection_cell.cell_output,
                output_checkpoint_cell.cell_output,
                output_withdraw_cell,
            ])
            .set_outputs_data(vec![
                output_selection_cell.cell_data.pack(),
                output_checkpoint_cell.cell_data.pack(),
                output_withdraw_data.pack(),
            ])
            .set_cell_deps(cell_deps)
            .build();

        let tx_view = self.balance_tx_capacity_by_identity(
            ctx.clone(),
            &tx_view,
            FeeRate(DEFAULT_FEE_RATE),
            payload.admin_id.try_into().unwrap(),
        ).await?;

        let script_grpups = self.get_tx_script_groups(&tx_view)?;
        Ok(TransactionCompletionResponse::new(
            tx_view.into(),
            script_grpups,
        ))
    }

    pub(crate) async fn inner_build_cross_chain_transfer_tx(
        &self,
        ctx: Context,
        payload: CrossChainTransferPayload,
    ) -> InnerResult<TransactionCompletionResponse> {
        let sender = parse_address(&payload.sender)
            .map_err(|e| CoreError::ParseAddressError(e.to_string()))?;
        let receiver = parse_address(&payload.receiver)
            .map_err(|e| CoreError::ParseAddressError(e.to_string()))?;
        let amount: u128 = payload.amount.parse().unwrap();

        let input_user_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![self
                    .build_acp_cell(sender.payload().args())
                    .calc_script_hash()
                    .unpack()],
                vec![payload.udt_hash.clone()],
                None,
                None,
                Default::default(),
            )
            .await?
            .response
            .first()
            .cloned()
            .unwrap();
        let input_relayer_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![self
                    .build_acp_cell(receiver.payload().args())
                    .calc_script_hash()
                    .unpack()],
                vec![payload.udt_hash],
                None,
                None,
                Default::default(),
            )
            .await?
            .response
            .first()
            .cloned()
            .unwrap();

        let user_capacity: u64 = input_user_cell.cell_output.capacity().unpack();
        let output_user_cell = input_user_cell
            .cell_output
            .clone()
            .as_builder()
            .capacity((user_capacity - 1000).pack())
            .build();
        let user_sudt_amount = if payload.direction == 0 {
            decode_udt_amount(&input_user_cell.cell_data)
                .unwrap()
                .checked_add(amount)
                .unwrap()
        } else {
            decode_udt_amount(&input_user_cell.cell_data)
                .unwrap()
                .checked_sub(amount)
                .unwrap()
        };
        let output_user_cell_data = user_sudt_amount.to_le_bytes().to_vec();
        let output_relayer_cell = input_relayer_cell.cell_output.clone();
        let relayer_sudt_amount = if payload.direction == 0 {
            decode_udt_amount(&input_relayer_cell.cell_data)
                .unwrap()
                .checked_sub(amount)
                .unwrap()
        } else {
            decode_udt_amount(&input_relayer_cell.cell_data)
                .unwrap()
                .checked_add(amount)
                .unwrap()
        };
        let output_relayer_cell_data = relayer_sudt_amount.to_le_bytes().to_vec();

        let cell_deps = self.axon_cross_chain_tx_cell_deps.get_or_init(||
            self
                .build_cell_deps(&[ACP, SUDT])
                .expect("Failed to init axon cross chain transfer tx cell deps")
        ).clone();

        let tx_view = TransactionView::new_advanced_builder()
            .set_inputs(
                self.build_transfer_tx_cell_inputs(
                    &[input_user_cell, input_relayer_cell],
                    None,
                    HashMap::default(),
                )?,
            )
            .set_outputs(vec![
                output_relayer_cell,
                output_user_cell,
            ])
            .set_outputs_data(vec![
                output_relayer_cell_data.pack(),
                output_user_cell_data.pack(),
            ])
            .set_cell_deps(cell_deps)
            .build();

        let script_groups = self.get_tx_script_groups(&tx_view)?;

        let mut witnesses = build_witnesses(
            2,
            &script_groups,
            &HashSet::new(),
            &HashMap::new(),
        );
        if payload.direction == 0 {
            witnesses.push(payload.memo.as_bytes().pack());
        }

        let tx_view = tx_view
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build();

        Ok(TransactionCompletionResponse::new(
            tx_view.into(),
            script_groups,
        ))
    }

    pub(crate) async fn prebuild_issue_asset_tx(
        &self,
        ctx: Context,
        payload: IssueAssetPayload,
    ) -> InnerResult<TransactionCompletionResponse> {
        let input_omni_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![],
                vec![payload.omni_type_hash.clone()],
                None,
                None,
                PaginationRequest::default().limit(Some(1)),
            )
            .await?
            .response
            .first()
            .cloned()
            .ok_or_else(|| CoreError::CannotFindCell(OMNI_SCRIPT.to_string()))?;
        println!("input omni cell {:?}", input_omni_cell);
        let input_selection_cell = self
            .get_live_cells(
                ctx.clone(),
                None,
                vec![payload.selection_lock_hash.clone()],
                vec![],
                None,
                None,
                PaginationRequest::default().limit(Some(1)),
            )
            .await?
            .response
            .first()
            .cloned()
            .ok_or_else(|| CoreError::CannotFindCell(AXON_SELECTION_LOCK.to_string()))?;
        println!("input selection cell {:?}", input_selection_cell);

        let mint_amount: u128 = payload.amount.parse().unwrap();
        let mut omni_data = input_omni_cell.cell_data.clone().to_vec();
        let new_supply = u128::from_le_bytes(to_fixed_array(&omni_data[1..17])) + mint_amount;
        omni_data[1..17].swap_with_slice(&mut new_supply.to_le_bytes());

        let acp_data = Bytes::from(mint_amount.to_le_bytes().to_vec());
        let acp_cell =
            packed::CellOutputBuilder::default()
                .type_(
                    Some(self.build_sudt_script(
                        input_selection_cell.cell_output.lock().calc_script_hash(),
                    ))
                    .pack(),
                )
                .lock(
                    self.build_acp_cell(
                        hex::decode(&payload.admin_id.content.to_vec()[2..])
                            .unwrap()
                            .into(),
                    ),
                )
                .build_exact_capacity(Capacity::shannons(
                    (acp_data.len() + 10) as u64 * BYTE_SHANNONS,
                ))
                .unwrap();

        let cell_deps = self.axon_issue_asset_tx_cell_deps.get_or_init(||
            self
                .build_cell_deps(&[AXON_SELECTION_LOCK, OMNI_SCRIPT])
                .expect("Failed to init axon issue asset tx cell deps")
        ).clone();

        let tx_view = TransactionView::new_advanced_builder()
            .set_inputs(
                self.build_transfer_tx_cell_inputs(
                    &[
                        input_selection_cell.clone(),
                        input_omni_cell.clone(),
                    ],
                    None,
                    HashMap::default(),
                )?,
            )
            .set_outputs(vec![
                input_selection_cell.cell_output,
                input_omni_cell.cell_output,
                acp_cell,
            ])
            .set_outputs_data(vec![
                Default::default(),
                omni_data.pack(),
                acp_data.pack(),
            ])
            .set_cell_deps(cell_deps)
            .build();

        let tx_view = self.balance_tx_capacity_by_identity(
            ctx.clone(),
            &tx_view,
            FeeRate(DEFAULT_FEE_RATE),
            payload.admin_id.try_into().unwrap(),
        ).await?;

        let mut witnesses = unpack_output_data_vec(tx_view.witnesses());
        let omni_witness = generated::RcLockWitnessLockBuilder::default()
            .signature(
                generated::BytesOptBuilder::default()
                    .set(build_bytes_opt([0u8; 65].to_vec().into()))
                    .build(),
            )
            .build()
            .as_bytes();
        witnesses[1] = packed::WitnessArgsBuilder::default()
            .lock(Some(omni_witness).pack())
            .build()
            .as_bytes()
            .pack();

        let tx_view = tx_view
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build();

        let script_groups = self.get_tx_script_groups(&tx_view)?;
        Ok(TransactionCompletionResponse::new(
            tx_view.into(),
            script_groups,
        ))
    }

    pub(crate) async fn prebuild_init_axon_chain_tx(
        &self,
        ctx: Context,
        payload: InitChainPayload,
    ) -> InnerResult<TransactionCompletionResponse> {
        let (omni_cell, omni_cell_data) =
            self.build_omni_cell(payload.omni_config.clone(), payload.admin_id.clone())?;
        let (checkpoint_cell, checkpoint_cell_data) = self
            .build_checkpoint_cell(payload.check_point_config.clone(), payload.admin_id.clone())?;
        let (stake_cell, stake_cell_data) =
            self.build_stake_cell(payload.state_config.clone(), payload.admin_id.clone())?;
        let selection_cell =
            self.build_selection_cell(checkpoint_cell.lock().calc_script_hash().unpack())?;

        let tx_view = TransactionView::new_advanced_builder()
            .outputs(vec![
                selection_cell.clone(),
                omni_cell.clone(),
                checkpoint_cell.clone(),
                stake_cell.clone(),
            ])
            .outputs_data(vec![
                Default::default(),
                omni_cell_data.pack(),
                checkpoint_cell_data.pack(),
                stake_cell_data.pack(),
            ])
            .build();

        let tx_view = self.balance_tx_capacity_by_identity(
            ctx.clone(),
            &tx_view,
            FeeRate(DEFAULT_FEE_RATE),
            payload.admin_id.try_into().unwrap(),
        )
        .await?;

        let first_input_cell = tx_view.inputs().get(0).unwrap();

        // Update omni cell
        let omni_type_script = self.build_type_id_script(&first_input_cell, 1)?;
        let omni_type_hash = omni_type_script.calc_script_hash();
        let mut omni_lock_args = omni_cell.lock().args().raw_data().to_vec();
        omni_lock_args[22..].swap_with_slice(&mut omni_type_hash.raw_data().to_vec());
        let omni_lock = omni_cell
            .lock()
            .as_builder()
            .args(omni_lock_args.pack())
            .build();
        let omni_cell = omni_cell
            .as_builder()
            .type_(Some(omni_type_script).pack())
            .lock(omni_lock)
            .build();

        // Update checkpoint cell
        let checkpoint_type_script = self.build_type_id_script(&first_input_cell, 2)?;
        let checkpoint_type_hash = checkpoint_type_script.calc_script_hash();
        let checkpoint_lock_args = checkpoint_cell.lock().args().raw_data();
        let new_args = generated::CheckpointLockArgs::new_unchecked(checkpoint_lock_args)
            .as_builder()
            .type_id_hash(checkpoint_type_hash.into())
            .build();
        let checkpoint_lock = checkpoint_cell
            .lock()
            .as_builder()
            .args(new_args.as_bytes().pack())
            .build();
        let checkpoint_cell = checkpoint_cell
            .as_builder()
            .lock(checkpoint_lock)
            .type_(Some(checkpoint_type_script).pack())
            .build();

        // Update stake cell
        let stake_type_script = self.build_type_id_script(&first_input_cell, 3)?;
        let stake_type_hash = stake_type_script.calc_script_hash();
        let stake_lock_args = stake_cell.lock().args().raw_data();
        let new_args = generated::StakeLockArgs::new_unchecked(stake_lock_args)
            .as_builder()
            .type_id_hash(stake_type_hash.clone().into())
            .build();
        let stake_lock_script = stake_cell
            .lock()
            .as_builder()
            .args(new_args.as_bytes().pack())
            .build();
        let stake_cell = stake_cell
            .as_builder()
            .type_(Some(stake_type_script).pack())
            .lock(stake_lock_script)
            .build();

        // Update selection cell
        let omni_lock_hash = omni_cell.lock().calc_script_hash();
        let checkpoint_lock_hash = checkpoint_cell.lock().calc_script_hash();
        let new_args = generated::SelectionLockArgsBuilder::default()
            .omni_lock_hash(omni_lock_hash.into())
            .checkpoint_lock_hash(checkpoint_lock_hash.into())
            .build();
        let selection_lock_script = selection_cell
            .lock()
            .as_builder()
            .args(new_args.as_bytes().pack())
            .build();
        let selection_cell = selection_cell
            .as_builder()
            .lock(selection_lock_script)
            .build();

        let sudt_args = selection_cell.lock().calc_script_hash();
        let sudt_type_hash = self.build_sudt_script(sudt_args).calc_script_hash();

        // Updata omni data
        let mut omni_cell_data = omni_cell_data.to_vec();
        omni_cell_data[33..].swap_with_slice(&mut sudt_type_hash.raw_data().to_vec());

        // Update checkpoint data
        let checkpoint_cell_data = generated::CheckpointLockCellData::new_unchecked(checkpoint_cell_data)
            .as_builder()
            .sudt_type_hash(sudt_type_hash.clone().into())
            .stake_type_hash(stake_type_hash.clone().into())
            .build()
            .as_bytes();

        // Updata stake data
        let stake_cell_data = generated::StakeLockCellData::new_unchecked(stake_cell_data)
            .as_builder()
            .sudt_type_hash(sudt_type_hash.into())
            .build()
            .as_bytes();

        let tx_view = tx_view
            .as_advanced_builder()
            .outputs(vec![
                selection_cell,
                omni_cell,
                checkpoint_cell,
                stake_cell,
            ])
            .outputs_data(vec![
                Default::default(),
                omni_cell_data.pack(),
                checkpoint_cell_data.pack(),
                stake_cell_data.pack(),
            ])
            .build();

        let script_groups = self.get_tx_script_groups(&tx_view)?;
        Ok(TransactionCompletionResponse::new(
            tx_view.into(),
            script_groups,
        ))
    }

    async fn balance_tx_capacity_by_identity(&self, ctx: Context, tx_view: &TransactionView, fee_rate: FeeRate, identity: core_rpc_types::Identity) -> InnerResult<TransactionView> {
        let scripts = self.get_scripts_by_identity(
            ctx.clone(),
            identity,
            None,
        ).await?
            .iter()
            .map(|script| (script.clone(), packed::WitnessArgs::default()))
            .collect();

        Ok(
            tokio::task::block_in_place(
                || balance_tx_capacity(
                    &tx_view,
                    &CapacityBalancer {
                        fee_rate,
                        capacity_provider: CapacityProvider::new(scripts),
                        change_lock_script: None,
                        force_small_change_as_fee: None,
                    },
                    &mut *self.cell_collector.lock().unwrap(),
                    &self.tx_dep_provider,
                    &self.cell_dep_resolver,
                    &self.header_dep_resolver,
                ).map_err(CoreError::from)
            )?
        )
    }
}

fn convert_bytes(input: Bytes) -> Vec<packed::Byte> {
    input.into_iter().map(|i| packed::Byte::new(i)).collect()
}

fn build_bytes_opt(input: Bytes) -> Option<generated::Bytes> {
    let bytes = convert_bytes(input);
    let bytes = generated::BytesBuilder::default().extend(bytes).build();
    Some(bytes)
}
fn unpack_output_data_vec(outputs_data: packed::BytesVec) -> Vec<packed::Bytes> {
    outputs_data.into_iter().collect()
}
