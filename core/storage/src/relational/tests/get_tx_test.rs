use super::*;

#[tokio::test]
async fn test_get_txs() {
    let pool = connect_and_insert_blocks().await;
    let txs_from_db = pool
        .get_transactions(
            Context::new(),
            vec![],
            vec![],
            vec![],
            Some(Range::new(0, 9)),
            PaginationRequest::new(
                Some(Bytes::from(0i64.to_be_bytes().to_vec())),
                Order::Asc,
                Some(20),
                None,
                true,
            ),
        )
        .await
        .unwrap()
        .response;
    let tx_hashes_from_db: Vec<H256> = txs_from_db
        .iter()
        .map(|tx| tx.transaction_with_status.transaction.clone().unwrap().hash)
        .collect();

    let mut txs_from_json: Vec<ckb_jsonrpc_types::TransactionView> = vec![];
    for i in 0..10 {
        let block: ckb_jsonrpc_types::BlockView = read_block_view(i, BLOCK_DIR.to_string());
        let mut txs = block.transactions;
        txs_from_json.append(&mut txs);
    }
    let tx_hashes_from_json: Vec<H256> = txs_from_json.iter().map(|tx| tx.hash.clone()).collect();

    assert_eq!(tx_hashes_from_db, tx_hashes_from_json);
}

#[tokio::test]
async fn test_get_spent_transaction_hash() {
    let pool = connect_and_insert_blocks().await;
    let block: BlockView = read_block_view(0, BLOCK_DIR.to_string()).into();
    let tx = &block.transaction(0).unwrap();
    let outpoint = ckb_jsonrpc_types::OutPoint {
        tx_hash: tx.hash().unpack(), // 0xb50ef2272f9f72b11e21ec12bd1b8fc9136cafc25c197b6fd4c2eb4b19fa905c
        index: 0u32.into(),
    };
    let res = pool
        .get_spent_transaction_hash(Context::new(), outpoint.into())
        .await
        .unwrap();
    assert_eq!(res, None)
}

#[tokio::test]
async fn test_get_tx_timestamp() {
    let pool = connect_and_insert_blocks().await;
    let txs_from_db = pool
        .get_transactions(
            Context::new(),
            vec![],
            vec![],
            vec![],
            Some(Range::new(0, 9)),
            PaginationRequest::new(
                Some(Bytes::from(0i64.to_be_bytes().to_vec())),
                Order::Asc,
                Some(20),
                None,
                true,
            ),
        )
        .await
        .unwrap()
        .response;
    let timestamps: Vec<u64> = txs_from_db.iter().map(|tx| tx.timestamp).collect();

    let mut timestamps_from_json: Vec<u64> = vec![];
    for i in 0..10 {
        let block: ckb_jsonrpc_types::BlockView = read_block_view(i, BLOCK_DIR.to_string());
        let txs = block.transactions;
        for _ in txs {
            let timestamp = block.header.inner.timestamp.into();
            timestamps_from_json.push(timestamp);
        }
    }

    assert_eq!(timestamps_from_json, timestamps);
}
