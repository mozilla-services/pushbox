/// Error handling based on the failure crate
///
/// Only rocket's Handlers can render error responses w/ a contextual JSON
/// payload. So request guards should generally return VALIDATION_FAILED,
/// leaving error handling to the Handler (which in turn must take a Result of
/// request guards' fields).
///
/// HandlerErrors are rocket Responders (render their own error responses).
use std::fmt;
use std::result;

use failure::{Backtrace, Context, Error, Fail};
use rocket::http::Status;
use rocket::response::{Responder, Response};
use rocket::{response, Request};
use rocket_contrib::json::Json;

pub type Result<T> = result::Result<T, Error>;

pub type HandlerResult<T> = result::Result<T, HandlerError>;

/// Signal a request guard failure, propagated up to the Handler to render an
/// error response
pub const VALIDATION_FAILED: Status = Status::InternalServerError;

#[derive(Debug)]
pub struct HandlerError {
    inner: Context<HandlerErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum HandlerErrorKind {
    /// 401 Unauthorized
    #[fail(display = "Missing authorization header")]
    MissingAuth,
    #[fail(display = "Invalid authorization header: Incorrect Authorization Header Token")]
    InvalidAuthBadToken,
    #[fail(display = "Invalid authorization header: Incorrect Authorization Schema")]
    InvalidAuthBadSchema,
    #[fail(display = "Unauthorized: Invalid Authorization token")]
    UnauthorizedBadToken,
    #[fail(display = "Unauthorized: Missing Authorization Header")]
    UnauthorizedNoHeader,
    #[fail(display = "Unauthorized: FxA Error: {:?}", _0)]
    ServiceErrorFxA(String),
    // 404 Not Found
    //#[fail(display = "Not Found")]
    //NotFound,
    #[fail(display = "A database error occurred")]
    ServiceErrorDB,
    #[fail(display = "General error: {:?}", _0)]
    GeneralError(String),
    // Note: Make sure that if display has an argument, the label includes the argument,
    // otherwise the process macro parser will fail on `derive(Fail)`
    //#[fail(display = "Unexpected rocket error: {:?}", _0)]
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
            HandlerErrorKind::ServiceErrorDB => 501,
            HandlerErrorKind::ServiceErrorFxA(_) => 510,
            HandlerErrorKind::GeneralError(_) => 500,
        }
    }
}

impl HandlerError {
    pub fn kind(&self) -> &HandlerErrorKind {
        self.inner.get_context()
    }
}

impl Fail for HandlerError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<HandlerErrorKind> for HandlerError {
    fn from(kind: HandlerErrorKind) -> HandlerError {
        Context::new(kind).into()
    }
}

impl From<Context<HandlerErrorKind>> for HandlerError {
    fn from(inner: Context<HandlerErrorKind>) -> HandlerError {
        HandlerError { inner }
    }
}

/// Generate HTTP error responses for HandlerErrors
impl<'r> Responder<'r> for HandlerError {
    fn respond_to(self, request: &Request) -> response::Result<'r> {
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
