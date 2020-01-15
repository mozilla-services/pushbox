//! Rustbox: A Rust based implementation of the Firefox Accounts Sync Storage service
//!
//! This app provides the FxA sync storage service (a.k.a pushbox). The idea being that
//! WebPush allows for small messages, but large, multipart messages can be problematic
//! for multiple reasons. Instead, FxA would use Pushbox as an imtermediary store, and
//! send the UA a link to data that it could fetch.
//!

#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate rocket;

pub mod auth;
pub mod config;
pub mod db;
mod error;
mod logging;
pub mod server;
pub mod sqs;

use std::env;

use rocket::config::RocketConfig;

fn main() {
    // RocketConfig::init basically

    let rconfig = RocketConfig::read().unwrap_or_else(|_| {
        let path = env::current_dir()
            .unwrap()
            .join(&format!(".{}.{}", "default", "Rocket.toml"));
        RocketConfig::active_default_from(Some(&path)).unwrap()
    });

    // rocket::ignite basically
    let config = rconfig.active().clone();
    let rocket_serv = server::Server::start(rocket::custom(config));
    rocket_serv.unwrap().launch();
}
