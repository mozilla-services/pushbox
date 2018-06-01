use std::cmp;
use std::str::Utf8Error;
use std::{thread, time};

use rocket;
use rocket::config;
use rocket::fairing::AdHoc;
use rocket::http::Method;
use rocket::request::{FormItems, FromForm};
use rocket_contrib::json::Json;

use auth::{AuthType, FxAAuthenticator};
use config::ServerConfig;
use db::models::DatabaseManager;
use db::{self, Conn, MysqlPool};
use error::{HandlerError, HandlerErrorKind, HandlerResult};
use failure::Error;
use logging::RBLogger;
use sqs::{self, SyncEvent};

#[derive(Deserialize, Debug)]
pub struct DataRecord {
    ttl: u64,
    data: String,
}

#[derive(Debug)]
pub struct Options {
    pub index: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<String>,
}

// Convenience function to convert a Option result into a u64 value (or 0)
fn as_u64(opt: Result<String, Utf8Error>) -> u64 {
    opt.unwrap_or_else(|_| "0".to_owned())
        .parse::<u64>()
        .unwrap_or(0)
}

/// Valid GET options include:
///
///  * *index* - Start from a given index number.
///  * *limit* - Only return **limit** number of items.
///  * *status* - Friendly format to specify the state of the client:
///    * *new* - This is a new UA, that needs all pending records.
///    * *lost* - The UA is lost and just needs to get the latest index record.
impl<'f> FromForm<'f> for Options {
    type Error = ();

    fn from_form(items: &mut FormItems<'f>, _strict: bool) -> Result<Options, ()> {
        let mut opt = Options {
            index: None,
            limit: None,
            status: None,
        };

        for (key, val) in items {
            let decoded = val.url_decode();
            match key.to_lowercase().as_str() {
                "index" => opt.index = Some(as_u64(decoded)),
                "limit" => opt.limit = Some(as_u64(decoded)),
                "status" => {
                    opt.status = match decoded {
                        Ok(status) => Some(status),
                        Err(_) => None,
                    }
                }
                _ => {}
            }
        }
        Ok(opt)
    }
}

// Encapsulate the server.
pub struct Server {}

impl Server {
    fn process_message(pool: &MysqlPool, event: &SyncEvent) -> Result<(), Error> {
        let conn = &pool.get()?;
        db::models::DatabaseManager::delete(&conn, &event.uid, &event.id)?;
        Ok(())
    }

    pub fn start(rocket: rocket::Rocket) -> Result<rocket::Rocket, Error> {
        db::run_embedded_migrations(rocket.config())?;

        let db_pool = db::pool_from_config(rocket.config()).expect("Could not get pool");
        let sqs_config = rocket.config().clone();
        let sq_logger = RBLogger::new(rocket.config());
        if !cfg!(test) {
            // if we're not running a test, spawn the SQS handler for account/device deletes
            thread::spawn(move || {
                let sqs_handler = sqs::SyncEventQueue::from_config(&sqs_config, &sq_logger);
                loop {
                    if let Some(event) = sqs_handler.fetch() {
                        if let Err(e) = Server::process_message(&db_pool, &event) {
                            slog_error!(sq_logger.log, "Could not process message"; "error" => e.to_string());
                        };
                        if let Err(e) = sqs_handler.ack_message(&event) {
                            slog_error!(sq_logger.log, "Could not ack message"; "error" => e.to_string());
                        };
                    } else {
                        // sleep 5m
                        thread::sleep(time::Duration::from_secs(300));
                    }
                }
            });
        }

        Ok(rocket
            .attach(AdHoc::on_attach(|rocket| {
                // Copy the config into a state manager.
                let pool = db::pool_from_config(rocket.config()).expect("Could not get pool");
                let rbconfig = ServerConfig::new(rocket.config());
                let logger = RBLogger::new(rocket.config());
                slog_info!(logger.log, "sLogging initialized...");
                Ok(rocket.manage(rbconfig).manage(pool).manage(logger))
            }))
            .mount(
                "/v1/store",
                routes![read, read_opt, write, delete, delete_user],
            )
            .mount("/v1/", routes![status]))
    }
}

/// Check an Authorization token permission, defaulting to the proper schema check.
pub fn check_token(
    config: &ServerConfig,
    method: Method,
    device_id: &String,
    token: &HandlerResult<FxAAuthenticator>,
) -> Result<bool, HandlerError> {
    match token {
        Ok(token) => match token.auth_type {
            AuthType::FxAServer => check_server_token(config, method, device_id, token),
            AuthType::FxAOauth => check_fxa_token(config, method, device_id, token),
        },
        Err(_e) => Err(HandlerErrorKind::Unauthorized(String::from("Token invalid")).into()),
    }
}

/// Stub for FxA server token permission authentication.
pub fn check_server_token(
    _config: &ServerConfig,
    _method: Method,
    _device_id: &String,
    _token: &FxAAuthenticator,
) -> Result<bool, HandlerError> {
    // currently a stub for the FxA server token auth.
    // In theory, the auth mod already checks the token against config.
    Ok(true)
}

/// Check the permissions of the FxA token to see if read/write access is provided.
pub fn check_fxa_token(
    config: &ServerConfig,
    method: Method,
    device_id: &String,
    token: &FxAAuthenticator,
) -> Result<bool, HandlerError> {
    // call unwrap here because we already checked for instances.
    let scope = &token.scope;
    if scope.contains(&FxAAuthenticator::fxa_root(&config.auth_app_name)) {
        return Ok(true);
    }
    // Otherwise check for explicit allowances
    match method {
        Method::Put | Method::Post | Method::Delete => {
            if scope.contains(&format!(
                "{}send/{}",
                FxAAuthenticator::fxa_root(&config.auth_app_name),
                device_id
            ))
                || scope.contains(&format!(
                    "{}send",
                    FxAAuthenticator::fxa_root(&config.auth_app_name)
                )) {
                return Ok(true);
            }
        }
        Method::Get => {
            if scope.contains(&format!(
                "{}recv/{}",
                FxAAuthenticator::fxa_root(&config.auth_app_name),
                device_id
            ))
                || scope.contains(&format!(
                    "{}recv",
                    FxAAuthenticator::fxa_root(&config.auth_app_name)
                )) {
                return Ok(true);
            }
        }
        _ => {}
    }
    Err(HandlerErrorKind::Unauthorized("Access Token Unauthorized".to_string()).into())
}

// Method handlers:::
// Apparently you can't set these on impl methods, must be at top level.
//  query string parameters for limit and index
#[get("/<user_id>/<device_id>?<options>")]
fn read_opt(
    conn: Conn,
    config: ServerConfig,
    logger: RBLogger,
    token: HandlerResult<FxAAuthenticator>,
    user_id: String,
    device_id: String,
    options: Options,
) -> HandlerResult<Json> {
    // 👩🏫 note that the "token" var is a HandlerResult wrapped Validate struct.
    // Validate::from_request extracts the token from the Authorization header, validates it
    // against FxA and the method, and either returns OK or an error. We need to reraise it to the
    // handler.
    slog_debug!(logger.log, "Handling Read"; "user_id" => &user_id, "device_id" => &device_id);
    check_token(&config, Method::Get, &device_id, &token)?;
    let max_index = DatabaseManager::max_index(&conn, &user_id, &device_id)?;
    let mut index = options.index;
    let mut limit = options.limit;
    match options.status.unwrap_or("".into()).to_lowercase().as_str() {
        "new" => {
            // New entry, needs all data
            index = None;
            limit = None;
            slog_debug!(logger.log, "Welcome new user"; "user_id" => &user_id);
        }
        "lost" => {
            // Just lost, needs just the next index.
            index = None;
            limit = Some(0);
            slog_debug!(logger.log, "Sorry, you're lost"; "user_id" => &user_id);
        }
        _ => {}
    };
    let messages =
        DatabaseManager::read_records(&conn, &user_id, &device_id, &index, &limit).unwrap();
    let mut msg_max: u64 = 0;
    for message in &messages {
        msg_max = cmp::max(msg_max, message.idx as u64);
    }
    slog_debug!(logger.log, "Found messages"; "len" => messages.len(), "user_id" => &user_id);
    // returns json {"status":200, "index": max_index, "messages":[{"index": #, "data": String}, ...]}
    let is_last = match limit {
        None => true,
        Some(0) => true,
        Some(_) => messages
            .last()
            .map(|last| (last.idx as u64) == max_index)
            .unwrap_or(true),
    };
    Ok(Json(json!({
        "last": is_last,
        "index": msg_max,
        "status": 200,
        "messages": messages
    })))
}

#[get("/<user_id>/<device_id>")]
fn read(
    conn: Conn,
    config: ServerConfig,
    logger: RBLogger,
    token: HandlerResult<FxAAuthenticator>,
    user_id: String,
    device_id: String,
) -> HandlerResult<Json> {
    read_opt(
        conn,
        config,
        logger,
        token,
        user_id,
        device_id,
        Options {
            index: None,
            limit: None,
            status: Some(String::from("start")),
        },
    )
}

/// Write the user data to the database.
#[post("/<user_id>/<device_id>", data = "<data>")]
fn write(
    conn: Conn,
    config: ServerConfig,
    logger: RBLogger,
    token: HandlerResult<FxAAuthenticator>,
    user_id: String,
    device_id: String,
    data: Json<DataRecord>,
) -> HandlerResult<Json> {
    check_token(&config, Method::Post, &device_id, &token)?;
    if config
        .test_data
        .get("auth_only")
        .unwrap_or(&config::Value::from(false))
        .as_bool()
        .unwrap_or(false)
    {
        // Auth testing, do not write to db.
        slog_info!(logger.log, "Auth Skipping database check.");
        return Ok(Json(json!({
            "status": 200,
            "index": -1,
        })));
    }
    slog_debug!(logger.log, "Writing new record:"; "user_id" => &user_id, "device_id" => &device_id);
    let response = DatabaseManager::new_record(
        &conn,
        &user_id,
        &device_id,
        &data.data,
        db::models::calc_ttl(data.ttl),
    );
    if response.is_err() {
        return Err(response.err().unwrap());
    }
    // returns json {"status": 200, "index": #}
    Ok(Json(json!({
        "status": 200,
        "index": response.unwrap(),
    })))
}

#[delete("/<user_id>/<device_id>")]
fn delete(
    conn: Conn,
    config: ServerConfig,
    token: HandlerResult<FxAAuthenticator>,
    user_id: String,
    device_id: String,
) -> HandlerResult<Json> {
    check_token(&config, Method::Delete, &device_id, &token)?;
    DatabaseManager::delete(&conn, &user_id, &device_id)?;
    // returns an empty object
    Ok(Json(json!({})))
}

#[delete("/<user_id>")]
fn delete_user(
    conn: Conn,
    config: ServerConfig,
    token: HandlerResult<FxAAuthenticator>,
    user_id: String,
) -> HandlerResult<Json> {
    check_token(&config, Method::Delete, &String::from(""), &token)?;
    DatabaseManager::delete(&conn, &user_id, &String::from(""))?;
    // returns an empty object
    Ok(Json(json!({})))
}

#[get("/status")]
fn status(config: ServerConfig) -> HandlerResult<Json> {
    let config = config;
    // TODO: check the database.

    Ok(Json(json!({
        "status": "Ok",
        "fxa_auth": config.fxa_host.clone(),
    })))
}

#[cfg(test)]
mod test {
    use rand::{distributions, thread_rng, Rng};
    use std::env;

    use rocket;
    use rocket::config::{Config, Environment, RocketConfig, Table};
    use rocket::http::Header;
    use rocket::local::Client;
    use serde_json;

    use super::Server;
    use auth::FxAAuthenticator;

    #[derive(Debug, Deserialize)]
    struct WriteResp {
        index: u64,
        status: u32,
    }

    #[derive(Debug, Deserialize)]
    struct Msg {
        index: u64,
        data: String,
    }

    #[derive(Debug, Deserialize)]
    struct ReadResp {
        status: u32,
        index: u64,
        last: bool,
        messages: Vec<Msg>,
    }

    fn rocket_config(test_data: Table) -> Config {
        let rconfig = RocketConfig::read().expect("failed to read config");
        let fxa_host = rconfig
            .active()
            .get_str("fxa_host")
            .unwrap_or("oauth.stage.mozaws.net");

        let db_url = env::var("ROCKET_DATABASE_URL")
            .unwrap_or(String::from("mysql://test:test@localhost/pushbox"));
        let config = Config::build(Environment::Development)
            .extra("fxa_host", fxa_host)
            .extra("database_url", db_url)
            .extra("dryrun", true)
            .extra("auth_app_name", "pushbox")
            .extra("test_data", test_data)
            .finalize()
            .unwrap();
        config
    }

    fn rocket_client(config: Config) -> Client {
        let test_rocket = Server::start(rocket::custom(config, true)).expect("test rocket failed");
        Client::new(test_rocket).expect("test rocket launch failed")
    }

    fn device_id() -> String {
        thread_rng()
            .sample_iter(&distributions::Alphanumeric)
            .take(8)
            .collect()
    }

    fn user_id() -> String {
        format!("test-{}", device_id())
    }

    fn default_config_data() -> Table {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![format!("{}send/bar", FxAAuthenticator::fxa_root("pushbox"))].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());
        test_data
    }

    #[test]
    fn test_valid_write() {
        let test_data = default_config_data();
        println!("test_data: {:?}", &test_data);
        let config = rocket_config(test_data);
        let client = rocket_client(config);
        let user_id = user_id();
        let url = format!("/v1/store/{}/{}", user_id, device_id());
        println!("URL: {}", url);
        let mut result = client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let body = &result.body_string().unwrap();
        assert!(result.status() == rocket::http::Status::raw(200));
        assert!(body.contains(r#""index":"#));
        assert!(body.contains(r#""status":200"#));

        // cleanup
        client
            .delete(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
    }

    #[test]
    fn test_valid_read() {
        let config = rocket_config(default_config_data());
        let client = rocket_client(config);
        let url = format!("/v1/store/{}/{}", user_id(), device_id());
        let mut write_result = client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let write_json: WriteResp = serde_json::from_str(
            &write_result
                .body_string()
                .expect("Empty body string for write"),
        ).expect("Could not parse write response body");
        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        let mut read_json: ReadResp = serde_json::from_str(
            &read_result
                .body_string()
                .expect("Empty body for read response"),
        ).expect("Could not parse read response");

        assert!(read_json.status == 200);
        assert!(read_json.messages.len() > 0);
        // a MySql race condition can cause this to fail.
        assert!(write_json.index <= read_json.index);

        // return the message at index
        read_result = client
            .get(format!("{}?index={}&limit=1", url, write_json.index))
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        read_json = serde_json::from_str(
            &read_result
                .body_string()
                .expect("Empty body for read query"),
        ).expect("Could not parse read query body");
        assert!(read_json.status == 200);
        assert!(read_json.messages.len() == 1);
        // a MySql race condition can cause these to fail.
        assert!(&read_json.index == &write_json.index);
        assert!(&read_json.messages[0].index == &write_json.index);

        // no data, no panic
        let empty_url = format!("/v1/store/{}/{}", user_id(), device_id());
        read_result = client
            .get(empty_url)
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        read_json = serde_json::from_str(
            &read_result
                .body_string()
                .expect("Empty body for read query"),
        ).expect("Could not parse read query body");
        assert!(read_json.status == 200);
        assert!(read_json.messages.len() == 0);

        // cleanup
        client
            .delete(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
    }

    #[test]
    fn test_valid_delete() {
        let config = rocket_config(default_config_data());
        let client = rocket_client(config);
        let user_id = user_id();
        let url = format!("/v1/store/{}/{}", user_id, device_id());
        client
            .post(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 60, "data":"Some Data"}"#)
            .dispatch();
        let mut del_result = client
            .delete(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(del_result.status() == rocket::http::Status::raw(200));
        let mut res_str = del_result.body_string().expect("Empty delete body string");
        assert!(res_str == "{}");
        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        res_str = read_result.body_string().expect("Empty read body string");
        let mut read_json: ReadResp =
            serde_json::from_str(&res_str).expect("Could not parse ready body");
        assert!(read_json.messages.len() == 0);

        let read_result = client
            .delete(format!("/v1/store/{}", user_id))
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        assert!(del_result.body_string() == None);

        let mut read_result = client
            .get(url.clone())
            .header(Header::new("Authorization", "bearer token"))
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();
        assert!(read_result.status() == rocket::http::Status::raw(200));
        read_json = serde_json::from_str(
            &read_result
                .body_string()
                .expect("Empty verification body string"),
        ).expect("Could not parse verification body string");
        assert!(read_json.messages.len() == 0);
    }

    // TODO: add tests for servertoken checks.
}
