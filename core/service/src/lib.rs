#![allow(clippy::mutable_key_type, dead_code)]

mod middleware;

// use middleware::{CkbRelayMiddleware, RelayMetadata};

use common::{anyhow::anyhow, utils::ScriptInfo, Context, NetworkType, Result};
use core_rpc::{
    CkbRpc, CkbRpcClient, MercuryRpcImpl, MercuryRpcServer, CURRENT_BLOCK_NUMBER,
    CURRENT_EPOCH_NUMBER, TX_POOL_CACHE,
};
use core_storage::{DBDriver, RelationalStorage, Storage};
use core_synchronization::Synchronization;

use ckb_jsonrpc_types::{RawTxPool, TransactionWithStatus};
use ckb_types::core::{BlockNumber, BlockView, EpochNumberWithFraction, RationalU256};
use ckb_types::{packed, H256};
use jsonrpsee_http_server::{HttpServerBuilder, HttpStopHandle};
use log::{error, info, warn, LevelFilter};
use tokio::time::{sleep, Duration};

use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::sync::Arc;

const GENESIS_NUMBER: u64 = 0;

#[derive(Clone, Debug)]
pub struct Service {
    store: RelationalStorage,
    ckb_client: CkbRpcClient,
    poll_interval: Duration,
    rpc_thread_num: usize,
    network_type: NetworkType,
    builtin_scripts: HashMap<String, ScriptInfo>,
    cellbase_maturity: RationalU256,
    cheque_since: RationalU256,
}

impl Service {
    pub fn new(
        max_connections: u32,
        center_id: u16,
        machine_id: u16,
        poll_interval: Duration,
        rpc_thread_num: usize,
        network_ty: &str,
        builtin_scripts: HashMap<String, ScriptInfo>,
        cellbase_maturity: u64,
        ckb_uri: String,
        cheque_since: u64,
        log_level: LevelFilter,
    ) -> Self {
        let ckb_client = CkbRpcClient::new(ckb_uri);
        let store = RelationalStorage::new(max_connections, center_id, machine_id, log_level);
        let network_type = NetworkType::from_raw_str(network_ty).expect("invalid network type");
        let cellbase_maturity = RationalU256::from_u256(cellbase_maturity.into());
        let cheque_since = RationalU256::from_u256(cheque_since.into());

        info!("Mercury running in CKB {:?}", network_type);

        Service {
            store,
            ckb_client,
            poll_interval,
            rpc_thread_num,
            network_type,
            builtin_scripts,
            cellbase_maturity,
            cheque_since,
        }
    }

    pub async fn init(
        &self,
        listen_address: String,
        db_driver: String,
        db_name: String,
        host: String,
        port: u16,
        user: String,
        password: String,
    ) -> HttpStopHandle {
        self.store
            .connect(
                DBDriver::from_str(&db_driver),
                &db_name,
                &host,
                port,
                &user,
                &password,
            )
            .await
            .unwrap();

        let server = HttpServerBuilder::default()
            .build(
                listen_address
                    .to_socket_addrs()
                    .expect("config listen_address parsed")
                    .next()
                    .expect("listen_address parsed"),
            )
            .unwrap();

        // let mut io_handler: MetaIoHandler<RelayMetadata, _> =
        //     MetaIoHandler::with_middleware(CkbRelayMiddleware::new(self.ckb_client.clone()));
        let mercury_rpc_impl = MercuryRpcImpl::new(
            self.store.clone(),
            self.builtin_scripts.clone(),
            self.ckb_client.clone(),
            self.network_type,
            self.cheque_since.clone(),
            self.cellbase_maturity.clone(),
        );

        info!("Mercury Running!");

        server
            .start(mercury_rpc_impl.into_rpc())
            .expect("Start jsonrpc http server")
    }

    pub async fn do_sync(&self, sync_task_size: usize, max_task_number: usize) -> Result<()> {
        let db_tip = self
            .store
            .get_tip(Context::new())
            .await?
            .map_or_else(|| 0, |t| t.0);
        let mercury_count = self.store.block_count().await?;
        let node_tip = self.ckb_client.get_tip_block_number().await?;

        if db_tip > node_tip {
            return Err(anyhow!("db tip is greater than node tip"));
        }

        let sync_handler = Synchronization::new(
            self.store.inner(),
            Arc::new(self.ckb_client.clone()),
            sync_task_size,
            max_task_number,
            node_tip,
        );

        if (!sync_handler.is_previous_in_update().await?)
            && node_tip
                .checked_sub(mercury_count)
                .ok_or_else(|| anyhow!("chain tip is less than db tip"))?
                < 1000
        {
            sync_handler.build_indexer_cell_table().await?;
            return Ok(());
        }

        log::info!("start sync");

        sync_handler.do_sync().await?;
        sync_handler.build_indexer_cell_table().await?;

        Ok(())
    }

    pub async fn start(&self, flush_pool_interval: u64) {
        let client_clone = self.ckb_client.clone();

        tokio::spawn(async move {
            update_tx_pool_cache(client_clone, flush_pool_interval).await;
        });

        self.run().await;
    }

    async fn run(&self) {
        let mut tip = 0;

        loop {
            if let Some((tip_number, tip_hash)) = self
                .store
                .get_tip(Context::new())
                .await
                .expect("get tip should be OK")
            {
                tip = tip_number;

                match self.get_block_by_number(tip_number + 1).await {
                    Ok(Some(block)) => {
                        if block.parent_hash().raw_data() == tip_hash.0.to_vec() {
                            info!("append {}, {}", block.number(), block.hash());
                            self.change_current_epoch(block.epoch().to_rational());
                            self.store
                                .append_block(Context::new(), block)
                                .await
                                .unwrap();
                        } else {
                            info!("rollback {}, {}", tip_number, tip_hash);
                            self.store
                                .rollback_block(Context::new(), tip_number, tip_hash)
                                .await
                                .unwrap();
                        }
                    }

                    Ok(None) => {
                        sleep(self.poll_interval).await;
                    }

                    Err(err) => {
                        error!("cannot get block from ckb node, error: {}", err);
                        sleep(self.poll_interval).await;
                    }
                }
            } else {
                match self.get_block_by_number(0).await {
                    Ok(Some(block)) => {
                        log::info!("append {} block", 0);
                        self.change_current_epoch(block.epoch().to_rational());
                        self.store
                            .append_block(Context::new(), block)
                            .await
                            .unwrap();
                    }

                    Ok(None) => {
                        sleep(self.poll_interval).await;
                    }

                    Err(err) => {
                        error!("cannot get block from ckb node, error: {}", err);
                        sleep(self.poll_interval).await;
                    }
                }
            }

            let _ = *CURRENT_BLOCK_NUMBER.swap(Arc::new(tip));
        }
    }

    async fn get_block_by_number(&self, block_number: BlockNumber) -> Result<Option<BlockView>> {
        let ret = self
            .ckb_client
            .get_blocks_by_number(vec![block_number])
            .await?
            .get(0)
            .cloned()
            .unwrap();

        Ok(ret.map(|b| b.into()))
    }

    pub async fn start_rpc_mode(&self) -> Result<()> {
        loop {
            let current_epoch = self.ckb_client.get_current_epoch().await?;
            let tip = self.ckb_client.get_tip_block_number().await?;

            let start_number: u64 = current_epoch.start_number.into();
            let epoch_length: u64 = current_epoch.length.into();
            let epoch_number: u64 = current_epoch.number.into();
            let index = tip - start_number + 1;

            let (epoch_number, index, epoch_length) = if index > epoch_length {
                let current_epoch = self.ckb_client.get_current_epoch().await?;
                let start_number: u64 = current_epoch.start_number.into();
                let epoch_length: u64 = current_epoch.length.into();
                let epoch_number: u64 = current_epoch.number.into();
                let index = tip - start_number + 1;
                (epoch_number, index, epoch_length)
            } else {
                (epoch_number, index, epoch_length)
            };
            let current_epoch =
                EpochNumberWithFraction::new_unchecked(epoch_number, index, epoch_length);

            let _ = *CURRENT_BLOCK_NUMBER.swap(Arc::new(tip));
            self.change_current_epoch(current_epoch.to_rational());

            sleep(Duration::from_secs(2)).await;
        }
    }

    fn change_current_epoch(&self, current_epoch: RationalU256) {
        let epoch = Arc::new(current_epoch);
        let _ = *CURRENT_EPOCH_NUMBER.swap(epoch);
    }
}

async fn update_tx_pool_cache(ckb_client: CkbRpcClient, flush_cache_interval: u64) {
    loop {
        match ckb_client.get_raw_tx_pool(Some(true)).await {
            Ok(raw_pool) => handle_raw_tx_pool(&ckb_client, raw_pool).await,
            Err(e) => error!("get raw tx pool error {:?}", e),
        }

        sleep(Duration::from_millis(flush_cache_interval)).await;
    }
}

async fn handle_raw_tx_pool(ckb_client: &CkbRpcClient, raw_pool: RawTxPool) {
    let mut input_set: HashSet<packed::OutPoint> = HashSet::new();
    let hashes = tx_hash_list(raw_pool);

    if let Ok(res) = ckb_client.get_transactions(hashes).await {
        for item in res.iter() {
            match item {
                Some(TransactionWithStatus {
                    transaction: Some(tx_view),
                    ..
                }) => {
                    tx_view.inner.inputs.iter().for_each(|input| {
                        input_set.insert(input.previous_output.clone().into());
                    });
                }

                _ => warn!("Get transaction from pool failed"),
            }
        }
    }

    let mut pool_cache = TX_POOL_CACHE.write();
    *pool_cache = input_set;
}

fn tx_hash_list(raw_pool: RawTxPool) -> Vec<H256> {
    match raw_pool {
        RawTxPool::Ids(mut ids) => {
            let mut ret = ids.pending;
            ret.append(&mut ids.proposed);
            ret
        }
        RawTxPool::Verbose(map) => {
            let mut ret = map.pending.into_iter().map(|(k, _v)| k).collect::<Vec<_>>();
            let mut proposed = map
                .proposed
                .into_iter()
                .map(|(k, _v)| k)
                .collect::<Vec<_>>();

            ret.append(&mut proposed);
            ret
        }
    }
}

#[cfg(test)]
mod tests {
    use ckb_types::{packed, prelude::*, H256};
    use common::utils::to_fixed_array;
    use rand::random;

    fn rand_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|_| random::<u8>()).collect()
    }

    #[test]
    fn test_byte32() {
        let bytes = rand_bytes(32);
        let byte32: packed::Byte32 = to_fixed_array::<32>(&bytes).pack();
        let h256 = H256::from_slice(&bytes).unwrap();

        assert_eq!(byte32.raw_data(), h256.0.to_vec());
    }
}
