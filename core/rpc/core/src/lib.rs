#![allow(clippy::mutable_key_type)]

mod error;
mod r#impl;
#[cfg(test)]
mod tests;

pub use r#impl::MercuryRpcImpl;

use common::{PaginationResponse, Result};
use core_rpc_types::error::MercuryRpcError;
use core_rpc_types::{
    indexer, AdjustAccountPayload, BlockInfo, DaoClaimPayload, DaoDepositPayload,
    DaoWithdrawPayload, GetBalancePayload, GetBalanceResponse, GetBlockInfoPayload,
    GetSpentTransactionPayload, GetTransactionInfoResponse, MercuryInfo, QueryTransactionsPayload,
    SimpleTransferPayload, TransactionCompletionResponse, TransferPayload, TxView,
};
use core_storage::DBInfo;

use ckb_jsonrpc_types::Uint64;
use ckb_types::{bytes::Bytes, H160, H256};
use jsonrpsee_http_server::types::Error;
use jsonrpsee_proc_macros::rpc;

type RpcResult<T> = Result<T, Error>;
type InnerResult<T> = Result<T, MercuryRpcError>;

#[rpc(server)]
pub trait MercuryRpc {
    #[method(name = "get_balance")]
    async fn get_balance(&self, payload: GetBalancePayload) -> RpcResult<GetBalanceResponse>;

    #[method(name = "get_block_info")]
    async fn get_block_info(&self, payload: GetBlockInfoPayload) -> RpcResult<BlockInfo>;

    #[method(name = "get_transaction_info")]
    async fn get_transaction_info(&self, tx_hash: H256) -> RpcResult<GetTransactionInfoResponse>;

    #[method(name = "query_transactions")]
    async fn query_transactions(
        &self,
        payload: QueryTransactionsPayload,
    ) -> RpcResult<PaginationResponse<TxView>>;

    #[method(name = "build_adjust_account_transaction")]
    async fn build_adjust_account_transaction(
        &self,
        payload: AdjustAccountPayload,
    ) -> RpcResult<Option<TransactionCompletionResponse>>;

    #[method(name = "build_transfer_transaction")]
    async fn build_transfer_transaction(
        &self,
        payload: TransferPayload,
    ) -> RpcResult<TransactionCompletionResponse>;

    #[method(name = "build_simple_transfer_transaction")]
    async fn build_simple_transfer_transaction(
        &self,
        payload: SimpleTransferPayload,
    ) -> RpcResult<TransactionCompletionResponse>;

    #[method(name = "register_address")]
    async fn register_addresses(&self, addresses: Vec<String>) -> RpcResult<Vec<H160>>;

    #[method(name = "get_mercury_info")]
    fn get_mercury_info(&self) -> RpcResult<MercuryInfo>;

    #[method(name = "get_db_info")]
    fn get_db_info(&self) -> RpcResult<DBInfo>;

    #[method(name = "build_dao_deposit_transaction")]
    async fn build_dao_deposit_transaction(
        &self,
        payload: DaoDepositPayload,
    ) -> RpcResult<TransactionCompletionResponse>;

    #[method(name = "build_dao_withdraw_transaction")]
    async fn build_dao_withdraw_transaction(
        &self,
        payload: DaoWithdrawPayload,
    ) -> RpcResult<TransactionCompletionResponse>;

    #[method(name = "build_dao_claim_transaction")]
    async fn build_dao_claim_transaction(
        &self,
        payload: DaoClaimPayload,
    ) -> RpcResult<TransactionCompletionResponse>;

    #[method(name = "get_spent_transaction")]
    async fn get_spent_transaction(&self, payload: GetSpentTransactionPayload)
        -> RpcResult<TxView>;

    #[method(name = "get_tip")]
    async fn get_tip(&self) -> RpcResult<Option<indexer::Tip>>;

    #[method(name = "get_cells")]
    async fn get_cells(
        &self,
        search_key: indexer::SearchKey,
        order: indexer::Order,
        limit: Uint64,
        after_cursor: Option<Bytes>,
    ) -> RpcResult<indexer::PaginationResponse<indexer::Cell>>;

    #[method(name = "get_cells_capacity")]
    async fn get_cells_capacity(
        &self,
        search_key: indexer::SearchKey,
    ) -> RpcResult<indexer::CellsCapacity>;

    #[method(name = "get_transactions")]
    async fn get_transactions(
        &self,
        search_key: indexer::SearchKey,
        order: indexer::Order,
        limit: Uint64,
        after_cursor: Option<Bytes>,
    ) -> RpcResult<indexer::PaginationResponse<indexer::Transaction>>;

    #[method(name = "get_ckb_uri")]
    async fn get_ckb_uri(&self) -> RpcResult<Vec<String>>;

    #[method(name = "get_live_cells_by_lock_hash")]
    async fn get_live_cells_by_lock_hash(
        &self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>,
    ) -> RpcResult<Vec<indexer::LiveCell>>;

    #[method(name = "get_capacity_by_lock_hash")]
    async fn get_capacity_by_lock_hash(
        &self,
        lock_hash: H256,
    ) -> RpcResult<indexer::LockHashCapacity>;

    #[method(name = "get_transactions_by_lock_hash")]
    async fn get_transactions_by_lock_hash(
        &self,
        lock_hash: H256,
        page: Uint64,
        per_page: Uint64,
        reverse_order: Option<bool>,
    ) -> RpcResult<Vec<indexer::CellTransaction>>;
}
