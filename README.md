# Pushbox - A rust implementation of Push/Sync long term storage

## What is it?

This is an internal project. mozilla needs the ability to store large data
chunks that may not fit perfectly within a standard WebPush message. PushBox
acts as an intermediary store for those chunks.

Messages are created by Firefox Accounts (FxA), stored here, and then a
WebPush message containing a URL that points back to this storage is sent
to the User Agent.

The User Agent can then fetch the data, decrypt it and do whatever it needs
to.

This project, once completed, will eventually replace the AWS Severless
PushBox project. It's being developed here because serverless can be a bit
greedy about what it grabs, and since PushBox is a rapid prototype, it's
good to treat it in a clean room environment.

See [API doc](
https://docs.google.com/document/d/1YT6gh125Tu03eM42Vb_LKjvgxc4qrGGZsty1_ajf2YM/)

## Requirements

The project requires Rust Nightly, a MySQL compliant data store, and
access to a [Firefox Accounts token verifier](https://github.com/mozilla/fxa-auth-server) system.


## Setting Up

1) Install Rust Nightly.

The rocket.rs [Getting Started](https://rocket.rs/guide/getting-started/)
document lists information on how to set that up.

2) create the pushbox MySQL user and database.

Because I'm horribly creative and because this is a WIP, I use "`test:test@localhost/pushbox`".
This is not recommended for production use. You can set your preferred
MySQL access credential information as "database_url" in the `Rocket.toml`
settings file (See [Rocket Config](https://rocket.rs/guide/configuration/#rockettoml)
information.)

3) Run `cargo run` to start the application, which (depending on the last
  commit) may actually start the program. YMMV.

## Running Docker Image

It is ***NOT*** advised to run the docker image in a production environment.
It's best suited for local development ***ONLY***.

Be sure to have `docker-compose` v. 1.21.0 or later installed.

1) From a dedicated screen (or tmux window)

$ `docker-compose up`

This will create two intertwined docker images:

***db_1*** - the database image. This image is a local test image. The database
can be accessed via `mysql -utest -ptest -h localhost --port 4306 pushbox`.

***app_1*** - the **pushbox** application. This is accessible via port
8000,
and uses the server authentication key of "[Correct_Horse_Battery_Staple_1](https://www.xkcd.com/936/)".

e.g.
` curl -H "Authorization: FxA-Server-Key Correct_Horse_Battery_Staple_1" "http://localhost:8000/v1/userid/deviceid"`

Note: No garbage collection is currently done for the database. Heavy use
might warrant deleting old records every so often.
