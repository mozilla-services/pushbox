use std::collections::HashMap;
use std::time::Duration;

use reqwest;
use rocket::request::{self, FromRequest};
use rocket::Outcome::{Failure, Success};
use rocket::{Request, State};

use error::{HandlerError, HandlerErrorKind, VALIDATION_FAILED};

use config::ServerConfig;
use logging::RBLogger;

/// Fetch FxA scopes for a requests Authentication header.
///
/// The `Authentication` header should contain the FxA token as
/// `bearer <tokenvalue>`.  This will attempt to query the FxA Authentication
/// server and will return the valid set of scopes. Due to various limitations,
/// your app will need to check the returned scopes for fine grain permissions.
///
#[derive(Debug)]
pub struct FxAAuthenticator {
    pub auth_type: AuthType,
    pub scope: Vec<String>,
}

#[derive(Debug)]
pub enum AuthType {
    FxAOauth,  // Authorization: (Bearer | FxA-Oauth-Token)
    FxAServer, // Authorization: (FxA-Server-Key)
}

#[derive(Clone, Deserialize, Debug)]
pub struct FxAResp {
    user: String,
    client_id: String,
    scope: Vec<String>,
}

impl FxAAuthenticator {
    pub fn fxa_root(app: &str) -> String {
        /// template for the FxA root.
        ///
        /// Rust requires that the first argument for `format!()` is a string literal,
        /// thus this is a function.
        format!("https://identity.mozilla.com/apps/{}/", app)
    }

    /// parse the request header and extract the Authorization header, send to
    /// FxA auth, and return the scope array.
    ///
    /// For `dryrun` settings:
    ///  this will pull `auth_app_name` from the managed memory configuration
    ///  object to spoof a response from FxA.
    ///
    /// For `test` configurations:
    ///  this will pull a HashTable from the managed memory configuration object
    ///  called '*fxa_response*` which contains the spoofed return data for
    /// Thus currently pulls a managed memory configuration object that contains
    /// an `.auth_app_name` String for `dryrun` and `test` configurations.
    fn from_fxa_oauth(
        token: String,
        config: &ServerConfig,
        logger: &RBLogger,
    ) -> request::Outcome<Self, HandlerError> {
        // Get the scopes from the verify server.
        let fxa_host = &config.fxa_host;
        let fxa_url = Self::fxa_root(fxa_host);
        let mut body = HashMap::new();
        body.insert("token", token);
        if config.dryrun {
            slog_debug!(logger.log, "Dryrun, skipping auth");
            return Success(FxAAuthenticator {
                auth_type: AuthType::FxAOauth,
                scope: vec![Self::fxa_root(&config.auth_app_name)],
            });
        }
        let client = match reqwest::Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(3))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                slog_crit!(logger.log, "Reqwest failure"; "err" => format!("{:?}", err));
                return Failure((
                    VALIDATION_FAILED,
                    HandlerErrorKind::Unauthorized(format!("Client error {:?}", err)).into(),
                ));
            }
        };
        let resp: FxAResp = if cfg!(test) {
            /*
            Sadly, there doesn't seem to be a good way to do this. We can't add a trait for mocking
            this because the FromRequest trait doesn't allow additional methods, we can't dummy
            out the reqwest call, the only thing we can modify and access is the config info.
            fortunately, the following are mostly boilerplate for calling out to the FxA server.
            */
            let data = config
                .test_data
                .get("fxa_response")
                .expect("Could not parse test fxa_response");
            let mut fscopes: Vec<String> = Vec::new();
            for scope in data["scope"].as_array().expect("Invalid scope array") {
                fscopes.push(
                    scope
                        .as_str()
                        .expect("Missing valid scope for test")
                        .to_string(),
                );
            }
            FxAResp {
                user: data["user"]
                    .as_str()
                    .expect("Missing user info for test")
                    .to_string(),
                client_id: data["client_id"]
                    .as_str()
                    .expect("Missing client_id for test")
                    .to_string(),
                scope: fscopes,
            }
        } else {
            // get the FxA Validiator response.
            let mut raw_resp = match client.post(&fxa_url).json(&body).send() {
                Ok(response) => response,
                Err(err) => {
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::Unauthorized(format!("Pushbox Server Error: {:?}", err))
                            .into(),
                    ))
                }
            };
            if !raw_resp.status().is_success() {
                // Log validation fail
                return Failure((
                    VALIDATION_FAILED,
                    HandlerErrorKind::Unauthorized("Missing Authorization Header".to_string())
                        .into(),
                ));
            };
            match raw_resp.json() {
                Ok(val) => val,
                Err(e) => {
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::Unauthorized(format!("FxA Server error: {:?}", e)).into(),
                    ))
                }
            }
        };
        Success(FxAAuthenticator {
            auth_type: AuthType::FxAOauth,
            scope: resp.scope.clone(),
        })
    }

    /// Minimal handshake security
    fn from_server_token(
        token: String,
        config: &ServerConfig,
    ) -> request::Outcome<Self, HandlerError> {
        if config.server_token == Some(token) {
            Success(FxAAuthenticator {
                auth_type: AuthType::FxAServer,
                scope: Vec::new(),
            })
        } else {
            Failure((
                VALIDATION_FAILED,
                HandlerErrorKind::Unauthorized("Invalid Authorization token".to_string()).into(),
            ))
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for FxAAuthenticator {
    type Error = HandlerError;

    /// Process the Authorization header and return the token.
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, HandlerError> {
        let logger = request
            .guard::<State<RBLogger>>()
            .expect("Logger missing")
            .inner();
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            // Get a copy of the rocket config from the request's managed memory.
            // There is no other way to get the rocket.config() from inside a request
            // handler.
            let config = request
                .guard::<State<ServerConfig>>()
                .expect("Application missing config")
                .inner();
            let auth_bits: Vec<&str> = auth_header.splitn(2, ' ').collect();
            slog_debug!(logger.log, "Checking auth token");
            if auth_bits.len() != 2 {
                slog_debug!(logger.log, "Server token missing elements"; "token" => &auth_header);
                return Failure((
                    VALIDATION_FAILED,
                    HandlerErrorKind::InvalidAuth(
                        "Incorrect Authorization Header Token".to_string(),
                    ).into(),
                ));
            };
            match auth_bits[0].to_lowercase().as_str() {
                "bearer" | "fxa-oauth-token" => {
                    slog_debug!(logger.log, "Found Oauth token");
                    return Self::from_fxa_oauth(auth_bits[1].into(), config, logger);
                }
                "fxa-server-key" => return Self::from_server_token(auth_bits[1].into(), config),
                _ => {
                    slog_debug!(logger.log, "Found Server token");
                    return Failure((
                        VALIDATION_FAILED,
                        HandlerErrorKind::InvalidAuth(
                            "Incorrect Authorization Header Schema".to_string(),
                        ).into(),
                    ));
                }
            }
        } else {
            // No Authorization header
            slog_info!(logger.log, "No Authorization Header found");
            return Failure((VALIDATION_FAILED, HandlerErrorKind::MissingAuth.into()));
        }
    }
}

#[cfg(test)]
mod test {
    // cargo test -- --no-capture

    use rocket;
    use rocket::config::{Config, Environment, RocketConfig, Table};
    use rocket::fairing::AdHoc;
    use rocket::http::Header;
    use rocket::local::Client;
    use rocket_contrib::json::Json;

    use super::FxAAuthenticator;
    use config::ServerConfig;
    use error::HandlerResult;
    use logging::RBLogger;

    struct StubServer {}
    impl StubServer {
        pub fn start(rocket: rocket::Rocket) -> HandlerResult<rocket::Rocket> {
            Ok(rocket
                .attach(AdHoc::on_attach(|rocket| {
                    // Copy the config into a state manager.
                    let rbconfig = ServerConfig::new(rocket.config());
                    let logger = RBLogger::new(rocket.config());
                    Ok(rocket.manage(rbconfig).manage(logger))
                }))
                .mount("", routes![auth_test_read_stub, auth_test_write_stub]))
        }
    }

    // The following stub function is used for testing only.
    #[get("/test/<device_id>")]
    fn auth_test_read_stub(
        token: HandlerResult<FxAAuthenticator>,
        device_id: String,
    ) -> HandlerResult<Json> {
        Ok(Json(json!({
            "status": 200,
            "scope": token?.scope,
            "device_id": device_id
        })))
    }

    // The following stub function is used for testing only.
    #[post("/test/<device_id>")]
    fn auth_test_write_stub(
        token: HandlerResult<FxAAuthenticator>,
        device_id: String,
    ) -> HandlerResult<Json> {
        Ok(Json(json!({
            "status": 200,
            "scope": token?.scope,
            "device_id": device_id
        })))
    }

    fn rocket_config(test_data: Table) -> Config {
        let rconfig = RocketConfig::read().expect("failed to read config");
        let fxa_host = rconfig
            .active()
            .get_str("fxa_host")
            .unwrap_or("oauth.stage.mozaws.net");

        Config::build(Environment::Development)
            .extra("fxa_host", fxa_host)
            .extra("dryrun", false)
            .extra("auth_app_name", "test")
            .extra("test_data", test_data)
            .finalize()
            .unwrap()
    }

    fn rocket_client(config: Config) -> Client {
        let test_rocket =
            StubServer::start(rocket::custom(config, true)).expect("test rocket failed");
        Client::new(test_rocket).expect("test rocket launch failed")
    }

    #[test]
    fn test_valid() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![FxAAuthenticator::fxa_root("test")].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());

        test_data.insert("auth_only".into(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "bearer tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(200));
    }

    #[test]
    fn test_no_auth() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![format!("{}send/bar", FxAAuthenticator::fxa_root("test"))].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#)
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_schema() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![FxAAuthenticator::fxa_root("test")].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());

        test_data.insert("auth_only".into(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "invalid tokentoken"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_no_schema() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![FxAAuthenticator::fxa_root("test")].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());

        test_data.insert("auth_only".into(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "invalid"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_no_token() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![FxAAuthenticator::fxa_root("test")].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());

        test_data.insert("auth_only".into(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", "bearer"))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

    #[test]
    fn test_bad_auth_blank() {
        let mut test_data = Table::new();
        let mut fxa_response = Table::new();
        fxa_response.insert("user".into(), "test".into());
        fxa_response.insert("client_id".into(), "test".into());
        fxa_response.insert(
            "scope".into(),
            vec![FxAAuthenticator::fxa_root("test")].into(),
        );
        test_data.insert("fxa_response".into(), fxa_response.into());

        test_data.insert("auth_only".into(), true.into());
        let client = rocket_client(rocket_config(test_data));
        let result = client
            .post("/test/test")
            .header(Header::new("Authorization", ""))
            .header(Header::new("Content-Type", "application/json"))
            .body(r#"{"ttl": 123, "data": "Some Data"}"#.to_string())
            .dispatch();
        assert!(result.status() == rocket::http::Status::raw(401))
    }

}
