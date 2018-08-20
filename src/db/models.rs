//! Database model functions.
use std::time::{SystemTime, UNIX_EPOCH};

use diesel::mysql::MysqlConnection;
use diesel::{
    self, 
    insert_into, 
    Connection, 
    ExpressionMethods, 
    OptionalExtension, 
    QueryDsl, 
    RunQueryDsl, 
    Queryable, Insertable,
};
use failure::ResultExt;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use super::schema::pushboxv1;
use error::{HandlerErrorKind, HandlerResult};

/// MySQL record and table definition for Pushbox
#[derive(Debug, Queryable, Insertable)]
#[table_name = "pushboxv1"]

pub struct Record {
    /// User identifier
    pub user_id: String,
    /// FxA Device Identifier
    pub device_id: String,
    /// Expiration date (in UTC seconds)
    pub ttl: i64,
    /// Pushbox record index
    pub idx: i64,
    /// Actual data to be stored.
    pub data: Vec<u8>,
}

/// Serialize the Pushbox Data Record into something that the JSON functions can process.
impl Serialize for Record {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.data.clone();
        let mut s = serializer.serialize_struct("Record", 2)?;
        let index = &self.idx;
        s.serialize_field("index", &(*index as u64))?;
        s.serialize_field("data", &String::from_utf8(data.to_vec()).unwrap())?;
        s.end()
    }
}

/// Convenience function to return the proper UTC "now"
pub fn now_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u64
}

/// Convenience function to return the UTC offset from "now"
pub fn calc_ttl(seconds: u64) -> u64 {
    now_utc() + seconds
}

/// The general data management object.
pub struct DatabaseManager {}

impl DatabaseManager {
    /// Return the greatest index number for a given user & device.
    pub fn max_index(conn: &MysqlConnection, user_id: &str, device_id: &str) -> HandlerResult<u64> {
        let max_index = pushboxv1::table
            .select(pushboxv1::idx)
            .filter(pushboxv1::user_id.eq(user_id))
            .filter(pushboxv1::device_id.eq(device_id))
            .order(pushboxv1::idx.desc())
            .first::<i64>(conn)
            .optional()
            .context(HandlerErrorKind::ServiceErrorDB)?
            .unwrap_or(0);
        Ok(max_index as u64)
    }

    /// Write a new data record for a User & Device
    pub fn new_record(
        conn: &MysqlConnection,
        user_id: &str,
        device_id: &str,
        data: &str,
        ttl: u64,
    ) -> HandlerResult<u64> {
        let record_index =
            conn.transaction(|| {
                insert_into(pushboxv1::table)
                    .values((
                        pushboxv1::user_id.eq(user_id),
                        pushboxv1::device_id.eq(device_id),
                        pushboxv1::ttl.eq(ttl as i64),
                        pushboxv1::data.eq(data.as_bytes()),
                    ))
                    .execute(conn)?;
                pushboxv1::table
                    .select(pushboxv1::idx)
                    .order(pushboxv1::idx.desc())
                    .first::<i64>(conn)
            }).context(HandlerErrorKind::ServiceErrorDB)?;
        Ok(record_index as u64)
    }

    /// Fetch all records for a given User & Device starting at Index and restricted to the
    /// first Limit results.
    pub fn read_records(
        conn: &MysqlConnection,
        user_id: &str,
        device_id: &str,
        index: &Option<u64>,
        limit: &Option<u64>,
    ) -> HandlerResult<Vec<Record>> {
        let mut query = pushboxv1::table
            .select((
                pushboxv1::user_id,   // NOTE: load() does not order these, so you should
                pushboxv1::device_id, // keep them in field order for Record{}
                pushboxv1::ttl,
                pushboxv1::idx,
                pushboxv1::data,
            ))
            .into_boxed();
        query = query
            .filter(pushboxv1::user_id.eq(user_id))
            .filter(pushboxv1::device_id.eq(device_id))
            .filter(pushboxv1::ttl.ge(now_utc() as i64));
        if let Some(index) = index {
            query = query.filter(pushboxv1::idx.ge(*index as i64));
        }
        if let Some(limit) = limit {
            query = query.limit(*limit as i64);
        }
        Ok(query
            .order(pushboxv1::idx)
            .load::<Record>(conn)
            .context(HandlerErrorKind::ServiceErrorDB)?
            .into_iter()
            .collect())
    }

    pub fn delete(conn: &MysqlConnection, user_id: &str, device_id: &str) -> HandlerResult<()> {
        let mut query = diesel::delete(pushboxv1::table).into_boxed();
        query = query.filter(pushboxv1::user_id.eq(user_id));
        if !device_id.is_empty() {
            query = query.filter(pushboxv1::device_id.eq(device_id));
        }
        query.execute(conn).context(HandlerErrorKind::ServiceErrorDB)?;
        Ok(())
    }
}
