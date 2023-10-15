use crate::domain::error::PassError;
use actix_session::{SessionGetError, SessionInsertError};
use actix_web::error::InternalError;
use actix_web::http::StatusCode;
use actix_web::ResponseError;
use openssl::error::ErrorStack;

impl ResponseError for PassError {
    fn status_code(&self) -> StatusCode {
        match self {
            PassError::Database { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            PassError::DuplicateKey { .. } => StatusCode::CONFLICT,
            PassError::NotFound { .. } => StatusCode::NOT_FOUND,
            PassError::CurrentlyUnavailable { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            PassError::Validation { .. } => StatusCode::BAD_REQUEST,
            PassError::Serialization { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            PassError::Crypto { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            PassError::Authentication { .. } => StatusCode::UNAUTHORIZED,
            PassError::Authorization { .. } => StatusCode::FORBIDDEN,
            PassError::WeakPassword { .. } => StatusCode::BAD_REQUEST,
            PassError::Runtime { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<PassError> for InternalError<PassError> {
    fn from(err: PassError) -> Self {
        match err {
            PassError::Database { .. } => {
                InternalError::new(err.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            }
            PassError::DuplicateKey { .. } => InternalError::new(err.clone(), StatusCode::CONFLICT),
            PassError::NotFound { .. } => InternalError::new(err.clone(), StatusCode::NOT_FOUND),
            PassError::CurrentlyUnavailable { .. } => {
                InternalError::new(err.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            }
            PassError::Validation { .. } => {
                InternalError::new(err.clone(), StatusCode::BAD_REQUEST)
            }
            PassError::Serialization { .. } => {
                InternalError::new(err.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            }
            PassError::Crypto { .. } => {
                InternalError::new(err.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            }
            PassError::Authentication { .. } => {
                InternalError::new(err.clone(), StatusCode::UNAUTHORIZED)
            }
            PassError::Authorization { .. } => {
                InternalError::new(err.clone(), StatusCode::FORBIDDEN)
            }
            PassError::WeakPassword { .. } => {
                InternalError::new(err.clone(), StatusCode::BAD_REQUEST)
            }
            PassError::Runtime { .. } => {
                InternalError::new(err.clone(), StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

impl From<jsonwebtoken::errors::Error> for PassError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        PassError::runtime(format!("jwt failed {:?}", err).as_str(), None)
    }
}

impl From<SessionInsertError> for PassError {
    fn from(err: SessionInsertError) -> Self {
        PassError::runtime(format!("session failed {:?}", err).as_str(), None)
    }
}

impl From<SessionGetError> for PassError {
    fn from(err: SessionGetError) -> Self {
        PassError::runtime(format!("session failed {:?}", err).as_str(), None)
    }
}

impl From<rustls::Error> for PassError {
    fn from(err: rustls::Error) -> Self {
        PassError::runtime(format!("TLS failed {:?}", err).as_str(), None)
    }
}

impl From<ErrorStack> for PassError {
    fn from(err: ErrorStack) -> Self {
        PassError::runtime(format!("SSL failed {:?}", err).as_str(), None)
    }
}
