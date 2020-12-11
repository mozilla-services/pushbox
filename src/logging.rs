use rocket::config::Config;
use rocket::request::{self, FromRequest};
use rocket::{Outcome, Request, State};
use slog::o;
use slog::Drain;

#[derive(Clone, Debug)]
pub struct RBLogger {
    pub log: slog::Logger,
}

impl RBLogger {
    pub fn new(_config: &Config) -> RBLogger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::CompactFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        RBLogger {
            log: slog::Logger::root(drain, o!()).new(o!()),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for RBLogger {
    type Error = ();

    fn from_request(req: &'a Request<'r>) -> request::Outcome<Self, ()> {
        Outcome::Success(req.guard::<State<'_, RBLogger>>().unwrap().inner().clone())
    }
}
