//! FxA uses SQS to broadcast events regarding a user's activities with FxA. We only
//! need to pay attention to the deletion events.
use std::convert::TryFrom;
use std::env;
use std::rc::Rc;
use std::time::Duration;

use rocket::Config;
use rusoto_core::Region;
use rusoto_sqs::{DeleteMessageRequest, Message, ReceiveMessageRequest, Sqs, SqsClient};
use slog::{debug, warn};
use tokio::time::timeout;

use crate::error::{HandlerError, HandlerErrorKind, Result};
use crate::logging::RBLogger;

/// An SQS FxA event.
#[derive(Default, Debug, Clone)]
pub struct SyncEvent {
    /// The type of event. We need to act only for `delete` or `device:delete`
    pub event: String,
    /// The FxA User Identifier.
    pub uid: String,
    /// The FxA Device Identifier.
    pub id: String,
    /// The SQS message acknowledgement handle.
    pub handle: String,
}

impl TryFrom<Message> for SyncEvent {
    type Error = HandlerError;

    fn try_from(msg: Message) -> Result<Self> {
        let body = msg
            .body
            .ok_or_else(|| HandlerErrorKind::ServiceErrorFxA("Missing body".to_owned()))?;
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| HandlerErrorKind::ServiceErrorFxA(e.to_string()))?;
        Ok(Self {
            event: parsed["event"].as_str().unwrap_or("").to_owned(),
            uid: parsed["uid"].as_str().unwrap_or("").to_owned(),
            id: match parsed.get("id") {
                None => "".to_owned(),
                Some(s) => s.as_str().unwrap_or("").to_owned(),
            },
            handle: msg.receipt_handle.unwrap_or_else(|| "".to_owned()),
        })
    }
}

/// Object for handling the FxA Sync SQS queue
#[derive(Clone)]
pub struct SyncEventQueue {
    sqs: Rc<SqsClient>,
    url: String,
    logger: RBLogger,
}

impl SyncEventQueue {
    /// Generate a new SyncEventQueue from the Rocket.toml config file and environment.
    /// This will pull the optional AWS region override from the "AWS_LOCAL_SQS" environment
    /// variable.
    ///
    /// Configuration Options:
    /// * **sqs_url**: AWS SWS url to fetch data from. Defaults to the dev FxA account change URL.
    pub fn from_config(config: &Config, logger: &RBLogger) -> SyncEventQueue {
        let region = env::var("AWS_LOCAL_SQS")
            .map(|endpoint| Region::Custom {
                endpoint,
                name: "env_var".to_string(),
            })
            .unwrap_or_default();
        let queue_url = config.get_str("sqs_url").unwrap_or(
            "https://sqs.us-east-1.amazonaws.com/927034868273/fxa-oauth-account-change-dev",
        );
        // Max wait_time is 20, so we'll pound away on SQS.
        SyncEventQueue {
            sqs: Rc::new(SqsClient::new(region)),
            url: queue_url.to_owned(),
            logger: logger.clone(),
        }
    }

    /// Acknowledge a received SQS message by deleting it from the queue.
    pub async fn ack_message(&self, event: &SyncEvent) -> Result<()> {
        let sqs = self.sqs.clone();
        let mut request = DeleteMessageRequest::default();
        request.queue_url = self.url.clone();
        request.receipt_handle = event.handle.clone();
        debug!(self.logger.log, "SQS Acking message {:?}", request);
        timeout(Duration::from_secs(1), sqs.delete_message(request))
            .await
            .map_err(|e| HandlerErrorKind::GeneralError(e.to_string()))?
            .map_err(|e| HandlerErrorKind::GeneralError(e.to_string()))?;
        Ok(())
    }

    /// Fetch message from sqs
    pub async fn fetch(&self) -> Option<SyncEvent> {
        let sqs = self.sqs.clone();
        // capture response via retry_if(move||{..})
        let mut request = ReceiveMessageRequest::default();
        request.queue_url = self.url.clone();
        let response = match timeout(Duration::from_secs(1), sqs.receive_message(request)).await {
            Ok(r) => match r {
                Ok(r) => r,
                Err(e) => {
                    warn!(self.logger.log, "SQS timed out: {:?}", e);
                    return None;
                }
            },
            Err(e) => {
                warn!(self.logger.log, "SQS Rec'v Error: {:?}", e);
                return None;
            }
        };
        debug!(self.logger.log, "SQS Got message; {:?}", response);
        if let Some(m) = response.messages {
            debug!(self.logger.log, "SQS Messages {:?}", m);
            let event = match SyncEvent::try_from(m[0].clone()) {
                Ok(ev) => ev,
                Err(err) => {
                    warn!(self.logger.log, "SQS Could not understand event: {:?}", err);
                    return None;
                }
            };
            debug!(self.logger.log, "SQS event: {:?}", event);
            self.ack_message(&event).await.unwrap_or_else(|e| {
                warn!(self.logger.log, "SQS could not ack message: {:?}", e);
            });
            if event.event.to_lowercase() == "delete"
                || event.event.to_lowercase() == "device:delete"
            {
                return Some(event);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use futures::executor::block_on;
    use rand;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::env;
    use std::rc::Rc;
    use std::thread;
    use std::time::Duration;

    use rocket::config::{self, Config, Table, Value};
    use rocket_contrib::json;
    use rusoto_core::Region;
    use rusoto_sqs::{self, Message, Sqs, SqsClient};
    use tokio::time::timeout;

    use super::{SyncEvent, SyncEventQueue};
    use crate::error::Result;
    use crate::logging::RBLogger;

    fn setup(queue_url: String) -> SyncEventQueue {
        let config = Config::new(config::Environment::Development);
        let logger = RBLogger::new(&config);
        let region = env::var("AWS_LOCAL_SQS")
            .map(|endpoint| Region::Custom {
                endpoint,
                name: "env_var".to_string(),
            })
            .unwrap_or(Region::default());
        SyncEventQueue {
            sqs: Rc::new(SqsClient::new(region)),
            url: queue_url,
            logger,
        }
    }

    async fn create_queue(queue: &SqsClient, queue_name: String) -> Result<String> {
        let mut request = rusoto_sqs::CreateQueueRequest::default();
        request.queue_name = format!("{}_{}", queue_name, rand::random::<u8>());
        let response = queue.create_queue(request).await.unwrap();
        Ok(response.queue_url.unwrap().to_owned())
    }

    async fn make_test_queue(queue: &SqsClient, queue_name: String) -> Result<String> {
        let mut request = rusoto_sqs::ListQueuesRequest::default();
        request.queue_name_prefix = Some(queue_name.to_string());
        let response = queue.list_queues(request).await.unwrap();
        match response.queue_urls {
            Some(queues) => {
                if queues.is_empty() {
                    return Ok(create_queue(queue, queue_name).await?);
                }
                let queue = queues.first().unwrap().to_string();
                Ok(queue)
            }
            None => Ok(create_queue(queue, queue_name).await?),
        }
    }

    async fn load_record(
        queue_name: String,
        data: String,
    ) -> (String, rusoto_sqs::SendMessageResult) {
        let region = env::var("AWS_LOCAL_SQS")
            .map(|endpoint| Region::Custom {
                endpoint,
                name: "env_var".to_string(),
            })
            .unwrap_or(Region::default());
        let queue = SqsClient::new(region);
        let queue_url = make_test_queue(&queue, queue_name).await.unwrap();
        let msg_request = rusoto_sqs::SendMessageRequest {
            message_body: data.clone(),
            queue_url: queue_url.clone(),
            ..Default::default()
        };
        (queue_url, queue.send_message(msg_request).await.unwrap())
    }

    async fn kill_queue(queue: &SyncEventQueue, queue_url: String, count: u8) {
        let mut request = rusoto_sqs::DeleteQueueRequest::default();
        request.queue_url = queue_url.clone();
        // Try a few times because, again, AWS needs time for these things...
        match timeout(
            Duration::from_secs(1),
            queue.sqs.clone().delete_queue(request),
        )
        .await
        {
            Ok(_) => return,
            Err(err) => {
                println!("Oops: {:?}, try:{:?}", err, count);
                if count > 3 {
                    panic!("Could not clean up queue {:?}", err);
                }
                thread::sleep(Duration::new(1, 0));
                block_on(kill_queue(queue, queue_url.clone(), count + 1));
            }
        };
    }

    #[test]
    fn test_convert_msg() {
        let valid_msg = Message {
            attributes: None,
            body: Some(
                "{\"event\":\"test\",\"id\":\"someid\",\"device\":\"somedevice\"}".to_owned(),
            ),
            md5_of_body: Some("ignored".to_owned()),
            md5_of_message_attributes: Some("ignored".to_owned()),
            message_attributes: Some(HashMap::new()),
            message_id: Some("whatever".to_owned()),
            receipt_handle: Some("whatever".to_owned()),
        };
        let mut invalid_msg = valid_msg.clone();
        invalid_msg.body = None;
        match SyncEvent::try_from(invalid_msg) {
            Ok(d) => {
                panic!("Got something from nothing! {:?}", d);
            }
            Err(e) => {
                println!("Got error {:?}", e);
            }
        };
        let event = SyncEvent::try_from(valid_msg).unwrap();
        assert_eq!(event.event, "test");
    }

    // Use `cargo test -- --ignored` to run this test.
    #[test]
    #[ignore]
    fn test_fetch_delete() {
        let data = json!({"event": "delete", "uid": "test_test"});
        // create a unique queue to prevent corruption.
        let (queue_url, _) = block_on(load_record(
            "rustbox_test_queue".to_owned(),
            data.to_string(),
        ));
        let mut options = Table::new();
        options.insert("sqs_url".to_owned(), Value::from(queue_url.clone()));
        let queue = setup(queue_url.clone());
        // Give AWS a couple of seconds to process things.
        thread::sleep(Duration::new(2, 0));
        match block_on(queue.fetch()) {
            Some(r) => {
                assert_eq!(&r.uid, "test_test");
                assert_eq!(&r.event, "delete")
            }
            None => {
                block_on(kill_queue(&queue, queue_url, 0));
                panic!("Message not found.");
            }
        };
        /*
                // TODO: fix these, or mock them because waiting 2s per loop is nuts.
                data = json!({"event": "device:delete", "uid": "test_test"});
                let (_, result) = load_record("rustbox_test_queue".to_owned(), data.to_string());
                thread::sleep(Duration::new(2,0));
                let response = match queue.fetch(){
                    Some(r) => {
                        println!("response: {:?}", r);
                        assert_eq!(&r.uid, "test_test");
                        assert_eq!(&r.event, "device:delete" )
                    }
                    None => {
                        kill_queue(&queue, queue_url);
                        panic!("Message not found.");
                    }
                };

                data = json!({"event": "something", "uid": "test_test"});
                let (_, result) = load_record("rustbox_test_queue".to_owned(), data.to_string());
                thread::sleep(Duration::new(2,0));
                let response = match queue.fetch(){
                    Some(r) => {
                        kill_queue(&queue, queue_url);
                        panic!("Message found");
                    }
                    None => {

                    }
                };
        */

        //TODO: Verify stuffs
        block_on(kill_queue(&queue, queue_url, 0));
    }
}
