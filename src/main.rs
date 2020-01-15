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

fn main() {
    let rocket_serv = server::Server::start(rocket::ignite());
    rocket_serv.unwrap().launch();
}
