//! Rustbox: A Rust based implementation of the Firefox Accounts Sync Storage service
//!
//! This app provides the FxA sync storage service (a.k.a pushbox). The idea being that
//! WebPush allows for small messages, but large, multipart messages can be problematic
//! for multiple reasons. Instead, FxA would use Pushbox as an imtermediary store, and
//! send the UA a link to data that it could fetch.
//!

#![feature(plugin, decl_macro, custom_derive, duration_extras, try_from)]
#![plugin(rocket_codegen)]
// #![cfg_attr(feature = "cargo-clippy", allow(new_ret_no_self))]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate slog;
extern crate futures;

extern crate mysql;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_contrib;
extern crate rusoto_core;
extern crate rusoto_sqs;
extern crate serde;
extern crate slog_async;
extern crate slog_json;
extern crate slog_stdlog;
extern crate slog_term;

pub mod auth;
pub mod config;
pub mod db;
mod error;
mod logging;
pub mod server;
pub mod sqs;

fn main() {
    let rocket_serv = server::Server::start(rocket::ignite());
    rocket_serv.unwrap().launch();
}
