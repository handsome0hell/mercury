pub const BYTE_SHANNONS: u64 = 100_000_000;
pub const STANDARD_SUDT_CAPACITY: u64 = 142 * BYTE_SHANNONS;
pub const CHEQUE_CELL_CAPACITY: u64 = 162 * BYTE_SHANNONS;
pub const MIN_CKB_CAPACITY: u64 = 61 * BYTE_SHANNONS;
pub const WITHDRAWING_DAO_CELL_OCCUPIED_CAPACITY: u64 = 102 * BYTE_SHANNONS;
pub const INIT_ESTIMATE_FEE: u64 = BYTE_SHANNONS / 1000;
pub const DEFAULT_FEE_RATE: u64 = 1000;
pub const MAX_ITEM_NUM: usize = 1000;
pub const MIN_DAO_CAPACITY: u64 = 200 * BYTE_SHANNONS;
pub const MIN_DAO_LOCK_PERIOD: u64 = 180;
pub const TYPE_ID_SCRIPT: &str = "type_id";
pub const OMNI_SCRIPT: &str = "omni";

pub const fn ckb(num: u64) -> u64 {
    num * BYTE_SHANNONS
}
