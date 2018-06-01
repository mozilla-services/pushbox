//! Pushbox configuration options
//!
use rocket::config::{Config, Table};
use rocket::request::{self, FromRequest};
use rocket::{Outcome, Request, State};

/// Configuration options for Pushbox
// Due to some private variables, this must be defined in the same module as rocket.manage()
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// FxA OAuth host (default: `oauth.stage.mozaws.net`)
    pub fxa_host: String,
    /// Skip authorization checks if set to "true" (default: `false`)
    pub dryrun: bool,
    /// Default Time To Live for stored data (default: `3600`s)
    pub default_ttl: u64,
    /// FxA OAuth application name used in scopes (default: `pushbox`)
    pub auth_app_name: String,
    /// Testing data (used only in unit tests)
    pub test_data: Table,
    /// FxA Server Key Value (default `None`)
    pub server_token: Option<String>,
}

/// Helper functions to pull values from the private config.
impl ServerConfig {
    pub fn new(config: &Config) -> ServerConfig {
        // Transcode rust Config values
        ServerConfig {
            fxa_host: String::from(
                config
                    .get_str("fxa_host")
                    .unwrap_or("oauth.stage.mozaws.net"),
            ),
            dryrun: config.get_bool("dryrun").unwrap_or(false),
            default_ttl: config.get_float("default_ttl").unwrap_or(3600.0) as u64,
            auth_app_name: config
                .get_str("auth_app_name")
                .unwrap_or("pushbox")
                .replace(" ", ""),
            server_token: match config.get_str("server_token") {
                Ok(token) => Some(token.to_string()),
                Err(_) => None,
            },
            test_data: config
                .get_table("test_data")
                .unwrap_or(&Table::new())
                .clone(),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for ServerConfig {
    type Error = ();

    /// Automagically reutrn the configuration from the guarded rocket data for a request handler
    fn from_request(req: &'a Request<'r>) -> request::Outcome<Self, ()> {
        Outcome::Success(req.guard::<State<ServerConfig>>().unwrap().inner().clone())
    }
}
