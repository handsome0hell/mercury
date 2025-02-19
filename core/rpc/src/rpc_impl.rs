mod adjust_account;
mod build_tx;
mod consts;
mod operation;
mod query;
pub(crate) mod utils;

pub use crate::rpc_impl::consts::{
    ckb, BYTE_SHANNONS, CHEQUE_CELL_CAPACITY, DEFAULT_FEE_RATE, INIT_ESTIMATE_FEE, MAX_ITEM_NUM,
    MIN_CKB_CAPACITY, MIN_DAO_CAPACITY, MIN_DAO_LOCK_PERIOD, STANDARD_SUDT_CAPACITY,
    WITHDRAWING_DAO_CELL_OCCUPIED_CAPACITY,
};

use crate::error::{RpcError, RpcErrorMessage, RpcResult};
use crate::rpc_impl::build_tx::calculate_tx_size;
use crate::types::{
    indexer, indexer_legacy, AdjustAccountPayload, BlockInfo, DaoClaimPayload, DaoDepositPayload,
    DaoWithdrawPayload, GetBalancePayload, GetBalanceResponse, GetBlockInfoPayload,
    GetSpentTransactionPayload, GetTransactionInfoResponse, MercuryInfo, QueryTransactionsPayload,
    SimpleTransferPayload, TransactionCompletionResponse, TransferPayload, TxView,
};
use crate::{CkbRpc, MercuryRpcServer};

use common::utils::{parse_address, ScriptInfo};
use common::{
    anyhow, hash::blake2b_160, Address, AddressPayload, CodeHashIndex, Context, NetworkType,
    PaginationResponse, Result, ACP, CHEQUE, DAO, SECP256K1, SUDT,
};
use core_storage::{DBInfo, RelationalStorage};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use ckb_jsonrpc_types::Uint64;
use ckb_types::core::{BlockNumber, RationalU256};
use ckb_types::{bytes::Bytes, packed, prelude::*, H160, H256};
use clap::crate_version;
use dashmap::DashMap;
use jsonrpsee_http_server::types::Error;
use parking_lot::RwLock;

use std::collections::{HashMap, HashSet};
use std::{str::FromStr, sync::Arc, thread::ThreadId};

lazy_static::lazy_static! {
    pub static ref TX_POOL_CACHE: RwLock<HashSet<packed::OutPoint>> = RwLock::new(HashSet::new());
    pub static ref CURRENT_BLOCK_NUMBER: ArcSwap<BlockNumber> = ArcSwap::from_pointee(0u64);
    pub static ref CURRENT_EPOCH_NUMBER: ArcSwap<RationalU256> = ArcSwap::from_pointee(RationalU256::zero());
    pub static ref ACP_USED_CACHE: DashMap<ThreadId, Vec<packed::OutPoint>> = DashMap::new();
    pub static ref SECP256K1_CODE_HASH: ArcSwap<H256> = ArcSwap::from_pointee(H256::default());
    pub static ref SUDT_CODE_HASH: ArcSwap<H256> = ArcSwap::from_pointee(H256::default());
    pub static ref ACP_CODE_HASH: ArcSwap<H256> = ArcSwap::from_pointee(H256::default());
    pub static ref CHEQUE_CODE_HASH: ArcSwap<H256> = ArcSwap::from_pointee(H256::default());
    pub static ref DAO_CODE_HASH: ArcSwap<H256> = ArcSwap::from_pointee(H256::default());
}

macro_rules! rpc_impl {
    ($self_: ident, $func: ident, $payload: expr) => {{
        let (_, collector) = common_logger::Span::root("trace_name");
        let _collector = common_logger::MercuryTrace::new(collector);

        $self_
            .$func(Context::new(), $payload)
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }};
}

pub struct MercuryRpcImpl<C> {
    storage: RelationalStorage,
    builtin_scripts: HashMap<String, ScriptInfo>,
    ckb_client: C,
    network_type: NetworkType,
    cheque_timeout: RationalU256,
    cellbase_maturity: RationalU256,
}

#[async_trait]
impl<C: CkbRpc> MercuryRpcServer for MercuryRpcImpl<C> {
    async fn get_balance(&self, payload: GetBalancePayload) -> RpcResult<GetBalanceResponse> {
        rpc_impl!(self, inner_get_balance, payload)
    }

    async fn get_block_info(&self, payload: GetBlockInfoPayload) -> RpcResult<BlockInfo> {
        rpc_impl!(self, inner_get_block_info, payload)
    }

    async fn get_transaction_info(&self, tx_hash: H256) -> RpcResult<GetTransactionInfoResponse> {
        rpc_impl!(self, inner_get_transaction_info, tx_hash)
    }

    async fn query_transactions(
        &self,
        payload: QueryTransactionsPayload,
    ) -> RpcResult<PaginationResponse<TxView>> {
        rpc_impl!(self, inner_query_transactions, payload)
    }

    async fn build_adjust_account_transaction(
        &self,
        payload: AdjustAccountPayload,
    ) -> RpcResult<Option<TransactionCompletionResponse>> {
        rpc_impl!(self, inner_build_adjust_account_transaction, payload)
    }

    async fn build_transfer_transaction(
        &self,
        payload: TransferPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        rpc_impl!(self, inner_build_transfer_transaction, payload)
    }

    async fn build_simple_transfer_transaction(
        &self,
        payload: SimpleTransferPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        rpc_impl!(self, inner_build_simple_transfer_transaction, payload)
    }

    async fn register_addresses(&self, addresses: Vec<String>) -> RpcResult<Vec<H160>> {
        let mut inputs: Vec<(H160, String)> = vec![];
        for addr_str in addresses {
            let address = match parse_address(&addr_str) {
                Ok(address) => address,
                Err(error) => {
                    return Err(Error::from(RpcError::from(RpcErrorMessage::CommonError(
                        error.to_string(),
                    ))))
                }
            };
            let lock = address_to_script(address.payload());
            let lock_hash = H160(blake2b_160(lock.as_slice()));
            inputs.push((lock_hash, addr_str));
        }

        rpc_impl!(self, inner_register_addresses, inputs)
    }

    fn get_mercury_info(&self) -> RpcResult<MercuryInfo> {
        Ok(MercuryInfo {
            network_type: NetworkType::Testnet,
            mercury_version: crate_version!().to_string(),
            ckb_node_version: "v0.101".to_string(),
            enabled_extensions: vec![],
        })
    }

    fn get_db_info(&self) -> RpcResult<DBInfo> {
        self.inner_get_db_info(Context::new())
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn build_dao_deposit_transaction(
        &self,
        payload: DaoDepositPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        rpc_impl!(self, inner_build_dao_deposit_transaction, payload)
    }

    async fn build_dao_withdraw_transaction(
        &self,
        payload: DaoWithdrawPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        rpc_impl!(self, inner_build_dao_withdraw_transaction, payload)
    }

    async fn build_dao_claim_transaction(
        &self,
        payload: DaoClaimPayload,
    ) -> RpcResult<TransactionCompletionResponse> {
        rpc_impl!(self, inner_build_dao_claim_transaction, payload)
    }

    async fn get_spent_transaction(
        &self,
        payload: GetSpentTransactionPayload,
    ) -> RpcResult<TxView> {
        rpc_impl!(self, inner_get_spent_transaction, payload)
    }

    async fn get_tip(&self) -> RpcResult<Option<indexer::Tip>> {
        self.inner_get_tip(Context::new())
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_cells(
        &self,
        search_key: indexer::SearchKey,
        order: indexer::Order,
        limit: Uint64,
        after_cursor: Option<Bytes>,
    ) -> RpcResult<indexer::PaginationResponse<indexer::Cell>> {
        self.inner_get_cells(Context::new(), search_key, order, limit, after_cursor)
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_cells_capacity(
        &self,
        search_key: indexer::SearchKey,
    ) -> RpcResult<indexer::CellsCapacity> {
        self.inner_get_cells_capacity(Context::new(), search_key)
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_transactions(
        &self,
        search_key: indexer::SearchKey,
        order: indexer::Order,
        limit: Uint64,
        after_cursor: Option<Bytes>,
    ) -> RpcResult<indexer::PaginationResponse<indexer::Transaction>> {
        self.inner_get_transaction(Context::new(), search_key, order, limit, after_cursor)
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_ckb_uri(&self) -> RpcResult<Vec<String>> {
        let res = self
            .ckb_client
            .local_node_info()
            .await?
            .addresses
            .iter()
            .map(|addr| addr.address.clone())
            .collect::<Vec<_>>();
        Ok(res)
    }

    async fn get_live_cells_by_lock_hash(
        &self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>,
    ) -> RpcResult<Vec<indexer_legacy::LiveCell>> {
        self.inner_get_live_cells_by_lock_hash(
            Context::new(),
            lock_hash,
            page,
            per_page,
            reverse_order,
        )
        .await
        .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_capacity_by_lock_hash(
        &self,
        lock_hash: H256,
    ) -> RpcResult<indexer_legacy::LockHashCapacity> {
        self.inner_get_capacity_by_lock_hash(Context::new(), lock_hash)
            .await
            .map_err(|err| Error::from(RpcError::from(err)))
    }

    async fn get_transactions_by_lock_hash(
        &self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>,
    ) -> RpcResult<Vec<indexer_legacy::CellTransaction>> {
        self.inner_get_transactions_by_lock_hash(
            Context::new(),
            lock_hash,
            page,
            per_page,
            reverse_order,
        )
        .await
        .map_err(|err| Error::from(RpcError::from(err)))
    }
}

impl<C: CkbRpc> MercuryRpcImpl<C> {
    pub fn new(
        storage: RelationalStorage,
        builtin_scripts: HashMap<String, ScriptInfo>,
        ckb_client: C,
        network_type: NetworkType,
        cheque_timeout: RationalU256,
        cellbase_maturity: RationalU256,
    ) -> Self {
        SECP256K1_CODE_HASH.swap(Arc::new(
            builtin_scripts
                .get(SECP256K1)
                .cloned()
                .unwrap()
                .script
                .code_hash()
                .unpack(),
        ));
        SUDT_CODE_HASH.swap(Arc::new(
            builtin_scripts
                .get(SUDT)
                .cloned()
                .unwrap()
                .script
                .code_hash()
                .unpack(),
        ));
        ACP_CODE_HASH.swap(Arc::new(
            builtin_scripts
                .get(ACP)
                .cloned()
                .unwrap()
                .script
                .code_hash()
                .unpack(),
        ));
        CHEQUE_CODE_HASH.swap(Arc::new(
            builtin_scripts
                .get(CHEQUE)
                .cloned()
                .unwrap()
                .script
                .code_hash()
                .unpack(),
        ));
        DAO_CODE_HASH.swap(Arc::new(
            builtin_scripts
                .get(DAO)
                .cloned()
                .unwrap()
                .script
                .code_hash()
                .unpack(),
        ));

        MercuryRpcImpl {
            storage,
            builtin_scripts,
            ckb_client,
            network_type,
            cheque_timeout,
            cellbase_maturity,
        }
    }
}

pub fn address_to_script(payload: &AddressPayload) -> packed::Script {
    payload.into()
}

pub fn parse_normal_address(addr: &str) -> Result<Address> {
    Address::from_str(addr).map_err(|e| anyhow::anyhow!("{:?}", e))
}

pub fn pubkey_to_secp_address(lock_args: Bytes) -> H160 {
    let pubkey_hash = H160::from_slice(&lock_args[0..20]).unwrap();
    let script = packed::Script::from(&AddressPayload::new_short(
        NetworkType::Testnet,
        CodeHashIndex::Sighash,
        pubkey_hash,
    ));

    H160::from_slice(&blake2b_160(script.as_slice())).unwrap()
}

pub fn minstant_elapsed(start: u64) -> f64 {
    (minstant::now() - start) as f64 * minstant::nanos_per_cycle() / 1000f64
}
