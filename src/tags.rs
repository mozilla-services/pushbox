use rocket::{
    request::{self, FromRequest},
    Config, Outcome, Request, State,
};
use serde::{
    ser::{SerializeMap, Serializer},
    Serialize,
};
use std::collections::{BTreeMap, HashMap};

use crate::error::{self, Result};

#[derive(Clone, Debug)]
pub struct Tags {
    pub tags: HashMap<String, String>,
    pub extra: HashMap<String, String>,
}

impl Default for Tags {
    fn default() -> Tags {
        Tags {
            tags: HashMap::new(),
            extra: HashMap::new(),
        }
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(self.tags.len()))?;
        for tag in self.tags.clone() {
            if !tag.1.is_empty() {
                seq.serialize_entry(&tag.0, &tag.1)?;
            }
        }
        seq.end()
    }
}

// Tags are extra data to be recorded in metric and logging calls.
// If additional tags are required or desired, you will need to add them to the
// mutable extensions, e.g.
// ```
//      let mut tags = request.extensions_mut().get::<Tags>();
//      tags.insert("SomeLabel".to_owned(), "whatever".to_owned());
// ```
// how you get the request (or the response, and it's set of `extensions`) to whatever
// function requires it, is left as an exercise for the reader.
impl Tags {
    pub fn extend(&mut self, tags: HashMap<String, String>) {
        self.tags.extend(tags);
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for Tags {
    type Error = error::HandlerError;

    fn from_request(req: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(req.guard::<State<Tags>>().unwrap().inner().clone())
    }
}

impl Tags {
    pub fn init(_config: &Config) -> Result<Self> {
        let tags = HashMap::new();
        let extra = HashMap::new();
        Ok(Tags { tags, extra })
    }
}

impl Into<BTreeMap<String, String>> for Tags {
    fn into(self) -> BTreeMap<String, String> {
        let mut result = BTreeMap::new();

        for (k, v) in self.tags {
            result.insert(k.clone(), v.clone());
        }

        result
    }
}
