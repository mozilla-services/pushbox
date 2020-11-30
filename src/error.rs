/// Error handling based on the failure crate
///
/// Only rocket's Handlers can render error responses w/ a contextual JSON
/// payload. So request guards should generally return VALIDATION_FAILED,
/// leaving error handling to the Handler (which in turn must take a Result of
/// request guards' fields).
///
/// HandlerErrors are rocket Responders (render their own error responses).
use backtrace::Backtrace;
use std::error::Error;
use std::fmt;
use std::result;

use rocket::http::Status;
use rocket::response::{Responder, Response};
use rocket::{response, Request};
use rocket_contrib::{json, json::Json};
use thiserror::Error;

pub type Result<T> = result::Result<T, HandlerError>;

pub type HandlerResult<T> = result::Result<T, HandlerError>;

/// Signal a request guard failure, propagated up to the Handler to render an
/// error response
pub const VALIDATION_FAILED: Status = Status::InternalServerError;

#[derive(Debug)]
pub struct HandlerError {
    kind: HandlerErrorKind,
    backtrace: Backtrace,
}

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum HandlerErrorKind {
    /// 401 Unauthorized
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("Invalid authorization header: Incorrect Authorization Header Token")]
    InvalidAuthBadToken,
    #[error("Invalid authorization header: Incorrect Authorization Schema")]
    InvalidAuthBadSchema,
    #[error("Unauthorized: Invalid Authorization token")]
    UnauthorizedBadToken,
    #[error("Unauthorized: Missing Authorization Header")]
    UnauthorizedNoHeader,
    #[error("Invalid Option: Bad index: {:?}", _0)]
    InvalidOptionIndex(String),
    #[error("Invalid Option: Bad limit: {:?}", _0)]
    InvalidOptionLimit(String),
    #[error("Invalid Option: Bad Status: {:?}", _0)]
    InvalidOptionStatus(String),
    #[error("Unauthorized: FxA Error: {:?}", _0)]
    ServiceErrorFxA(String),
    // 404 Not Found
    //#[error("Not Found")]
    //NotFound,
    #[error("A database error occurred")]
    ServiceErrorDB,
    #[error("General error: {:?}", _0)]
    GeneralError(String),
    // Note: Make sure that if display has an argument, the label includes the argument,
    // otherwise the process macro parser will fail on `derive(Fail)`
    //#[error("Unexpected rocket error: {:?}", _0)]
    //RocketError(rocket::Error), // rocket::Error isn't a std Error (so no #[cause])
    // Application Errors
}

impl HandlerErrorKind {
    /// Return a rocket response Status to be rendered for an error
    pub fn http_status(&self) -> Status {
        match self {
            // HandlerErrorKind::NotFound => Status::NotFound,
            HandlerErrorKind::ServiceErrorDB => Status::ServiceUnavailable,
            HandlerErrorKind::ServiceErrorFxA(_) => Status::BadGateway,
            HandlerErrorKind::GeneralError(_) => Status::InternalServerError,
            HandlerErrorKind::InvalidOptionIndex(_)
            | HandlerErrorKind::InvalidOptionLimit(_)
            | HandlerErrorKind::InvalidOptionStatus(_) => Status::BadRequest,
            _ => Status::Unauthorized,
        }
    }

    /// Return a unique errno code
    pub fn errno(&self) -> i32 {
        match self {
            HandlerErrorKind::MissingAuth => 100,
            HandlerErrorKind::InvalidAuthBadToken => 201,
            HandlerErrorKind::InvalidAuthBadSchema => 202,
            HandlerErrorKind::UnauthorizedBadToken => 400,
            HandlerErrorKind::UnauthorizedNoHeader => 401,
            HandlerErrorKind::InvalidOptionIndex(_) => 402,
            HandlerErrorKind::InvalidOptionLimit(_) => 403,
            HandlerErrorKind::InvalidOptionStatus(_) => 404,
            HandlerErrorKind::ServiceErrorDB => 501,
            HandlerErrorKind::ServiceErrorFxA(_) => 510,
            HandlerErrorKind::GeneralError(_) => 500,
        }
    }
}

impl HandlerError {
    pub fn kind(&self) -> &HandlerErrorKind {
        &self.kind
    }
}

impl Error for HandlerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

impl<T> From<T> for HandlerError
where
    HandlerErrorKind: From<T>,
{
    fn from(item: T) -> Self {
        HandlerError {
            kind: HandlerErrorKind::from(item),
            backtrace: Backtrace::new(),
        }
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}\nBacktrace:\n{:?}", self.kind, self.backtrace)?;

        // Go down the chain of errors
        let mut error: &dyn Error = &self.kind;
        while let Some(source) = error.source() {
            write!(f, "\n\nCaused by: {}", source)?;
            error = source;
        }

        Ok(())
    }
}

/// Generate HTTP error responses for HandlerErrors
impl<'r> Responder<'r> for HandlerError {
    fn respond_to(self, request: &Request<'_>) -> response::Result<'r> {
        let status = self.kind().http_status();
        let json = Json(json!({
            "code": status.code,
            "errno": self.kind().errno(),
            "error": format!("{}", self)
        }));
        Response::build_from(json.respond_to(request)?)
            .status(status)
            .ok()
    }
}
