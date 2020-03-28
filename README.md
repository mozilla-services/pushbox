[![License: MPL 2.0][mpl-svg]][mpl]
[![Test Status][travis-badge]][travis]
[![Build Status][circleci-badge]][circleci]
[![Connect to Matrix via the Riot webapp][matrix-badge]][matrix]

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

# API

Pushbox is normally called via a HTTP interface using Authorized calls. Responses are generally JSON objects with appropriate HTTP status codes to indicate success/failure.

## Authorization

All calls to Pushbox require authorization. Authorization is specified by the `Authorization` header and can be either via a Server-Key or using Firefox Accounts OAuth token scopes. The method of authorization shall be determined and set by operations. It is **strongly** suggested that if Server-Key is used, access to PushBox be limited to an ACL of calling Sync servers. 

e.g.

```
Authorization: fxa-server-key Correct-Horse-Battery-Staple-1
```


## GET /v1/store/< user> /< device >[?< options >]

Fetch data for a `<user>` on a `<device>`. 

Options may be one or more of the following:

* *index* - offset index to being new messages.
* *limit* - maximum number of messages to return. This will include the next index value to use. 
* *status* - Quick set the index and limit values:
  * *new* - client is new, and needs all records.
  * *lost* - client only needs latest index.

The return value is JSON structure: 

```javascript
{ "last": true, /* boolean indicating this is the last data block */
  "index": 123, /* the highest message index value returned */
  "status": 200, /* HTTP status for result */
  "messages": [
    {"index": 123, /* Message block index */
     "data": "aBc1..." /* encrypted data block */
    }, ...
  ]
}
```

## POST /v1/store/< user >/< device >

Write a databblock for a `<user>` on `<device>`

The body of the post message is a JSON structure:

```javascript
{"ttl": 3600, /* Time for the data to live in seconds.*/
 "data": "aBc1..." /* Encrypted data block to store */
}
```

**NOTE:** Please be certain to encrypt the body of the data you wish to store. No encryption is done on the server side, and even if it was, there's no guarantee that it couldn't be reversed by a disgruntled employee or malicious agent.

The returned value is a JSON structure:

```javascript
{
  "status": 200, /* The HTTP status for the result */
  "index": 123 /* the index number of the stored record */
}
```

## DELETE /v1/store/< user >[/< device >]

Delete all records for a given user or just a given user's device.

This call returns just an empty object.


## GET /__heartbeat__

Return the status of the server.

This call is only used for server status checks.


## GET /__lbheartbeat__

Return a light weight status check (200 OK).

This call is only used for the Load Balancer's check.


## GET /__version__

Return a JSON response of the version information of the server.


# Database

Pushbox requires a configured MySQL compliant server. Pushbox requires the configuration file to contain the proper credentials, but will create any require table or indexes. Currently, there is no garbage collection done for expired, unread records. It is suggested that a regularly scheduled command be created to run 

```sql
DELETE from pushboxv1 where TTL < unix_timestamp();
```

This function may be added to pushbox at a later date.

[mpl-svg]: https://img.shields.io/badge/License-MPL%202.0-blue.svg
[mpl]: https://opensource.org/licenses/MPL-2.0
[travis-badge]: https://travis-ci.org/mozilla-services/pushbox.svg?branch=master
[travis]: https://travis-ci.org/mozilla-services/pushbox
[circleci-badge]: https://circleci.com/gh/mozilla-services/pushbox.svg?style=shield&circle-token=074ae89011d1a7601378c41a4351e1e03f1e8177
[circleci]: https://circleci.com/gh/mozilla-services/pushbox
[matrix-badge]: https://img.shields.io/badge/chat%20on%20[m]-%23push%3Amozilla.org-blue
[matrix]: https://chat.mozilla.org/#/room/#push:mozilla.org
