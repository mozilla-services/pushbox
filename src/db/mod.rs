//! Database module
pub mod models;
pub mod schema;

use std::ops::Deref;
use std::result::Result as StdResult;

use diesel::mysql::MysqlConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::{
    dsl::sql, result::Error as DieselError, sql_types::Integer, Connection, QueryDsl, RunQueryDsl,
};

use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::{Config, Outcome, Request, State};

use self::schema::pushboxv1;
use crate::error::{HandlerErrorKind, Result};

pub type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;

embed_migrations!();

/// Run the diesel embedded migrations
///
/// Mysql DDL statements implicitly commit which could disrupt MysqlPool's
/// begin_test_transaction during tests. So this runs on its own separate conn.
pub fn run_embedded_migrations(config: &Config) -> Result<()> {
    let database_url = config
        .get_str("database_url")
        .map_err(|_| {
            HandlerErrorKind::GeneralError("Invalid or undefined ROCKET_DATABASE_URL".to_string())
        })?
        .to_string();
    let conn = MysqlConnection::establish(&database_url)
        .map_err(|err| HandlerErrorKind::ConnectionErrorDb(err.to_string()))?;
    embedded_migrations::run(&conn)
        .map_err(|err| HandlerErrorKind::MigrationErrorDb(err.to_string()))?;
    Ok(())
}

/// Generate a pool of MySQL handlers from the Rocket.toml configuration file.
///
/// Options used:
/// * **database_url**: The DSN URL to access the MySQL Database.  `mysql://user:pass@host:port/database`
/// * **database_pool_max_size**: Max database pool size (default: 10)
pub fn pool_from_config(config: &Config) -> Result<MysqlPool> {
    let database_url = config
        .get_str("database_url")
        .map_err(|_| HandlerErrorKind::GeneralError("ROCKET_DATABASE_URL undefined".to_string()))?
        .to_string();
    let max_size = config.get_int("database_pool_max_size").unwrap_or(10) as u32;
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    let pman = Pool::builder()
        .max_size(max_size)
        .build(manager)
        .map_err(|e| HandlerErrorKind::GeneralError(e.to_string()))?;
    Ok(pman)
}

/// Determine if the database is healthy returning a DieselError otherwise
pub fn health_check(conn: &MysqlConnection) -> StdResult<(), DieselError> {
    match pushboxv1::table
        .select(sql::<Integer>("1"))
        .get_result::<i32>(conn)
    {
        Ok(_) | Err(DieselError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// An [r2d2.mysql] connection object
pub struct Conn(pub PooledConnection<ConnectionManager<MysqlConnection>>);

impl Deref for Conn {
    type Target = MysqlConnection;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Auto-magically return the guarded rocket.rs MySqlPool for a request handler.
impl<'a, 'r> FromRequest<'a, 'r> for Conn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, ()> {
        let pool = request.guard::<State<'_, MysqlPool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(Conn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ())),
        }
    }
}
