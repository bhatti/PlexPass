use hex::FromHexError;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

//
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PassError {
    Database {
        message: String,
        reason_code: Option<String>,
        retryable: bool,
    },
    DuplicateKey {
        message: String,
    },
    NotFound {
        message: String,
    },

    // This is a retry-able error.
    CurrentlyUnavailable {
        message: String,
        reason_code: Option<String>,
        retryable: bool,
    },
    Validation {
        message: String,
        reason_code: Option<String>,
    },
    Serialization {
        message: String,
    },
    Crypto {
        message: String,
    },
    Authentication {
        message: String,
    },
    Authorization {
        message: String,
    },
    WeakPassword {
        message: String,
    },
    Runtime {
        message: String,
        reason_code: Option<String>,
    },
}

impl PassError {
    pub fn database(message: &str, reason_code: Option<String>, retryable: bool) -> PassError {
        PassError::Database {
            message: message.into(),
            reason_code,
            retryable,
        }
    }

    pub fn duplicate_key(message: &str) -> PassError {
        PassError::DuplicateKey {
            message: message.into(),
        }
    }

    pub fn not_found(message: &str) -> PassError {
        PassError::NotFound {
            message: message.into(),
        }
    }

    pub fn unavailable(message: &str, reason_code: Option<String>, retryable: bool) -> PassError {
        PassError::CurrentlyUnavailable {
            message: message.into(),
            reason_code,
            retryable,
        }
    }

    pub fn validation(message: &str, reason_code: Option<String>) -> PassError {
        PassError::Validation {
            message: message.into(),
            reason_code,
        }
    }

    pub fn serialization(message: &str) -> PassError {
        PassError::Serialization {
            message: message.into(),
        }
    }

    pub fn crypto(message: &str) -> PassError {
        PassError::Crypto {
            message: message.into(),
        }
    }

    pub fn authentication(message: &str) -> PassError {
        PassError::Authentication {
            message: message.into(),
        }
    }

    pub fn authorization(message: &str) -> PassError {
        PassError::Authorization {
            message: message.into(),
        }
    }

    pub fn weak_password(message: &str) -> PassError {
        PassError::WeakPassword {
            message: message.into(),
        }
    }

    pub fn runtime(message: &str, reason_code: Option<String>) -> PassError {
        PassError::Runtime {
            message: message.into(),
            reason_code,
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            PassError::Database { retryable, .. } => retryable.clone(),
            PassError::DuplicateKey { .. } => false,
            PassError::NotFound { .. } => false,
            PassError::CurrentlyUnavailable { retryable, .. } => retryable.clone(),
            PassError::Validation { .. } => false,
            PassError::Serialization { .. } => false,
            PassError::Crypto { .. } => false,
            PassError::Authentication { .. } => false,
            PassError::Authorization { .. } => false,
            PassError::WeakPassword { .. } => false,
            PassError::Runtime { .. } => false,
        }
    }
}

impl From<std::io::Error> for PassError {
    fn from(err: std::io::Error) -> Self {
        PassError::runtime(format!("serde validation {:?}", err).as_str(), None)
    }
}

impl From<serde_json::Error> for PassError {
    fn from(err: serde_json::Error) -> Self {
        PassError::serialization(format!("serde validation {:?}", err).as_str())
    }
}

impl From<prometheus::Error> for PassError {
    fn from(err: prometheus::Error) -> Self {
        PassError::validation(format!("prometheus validation {:?}", err).as_str(), None)
    }
}

impl From<FromUtf8Error> for PassError {
    fn from(err: FromUtf8Error) -> Self {
        PassError::runtime(format!("utf8 conversion failed {:?}", err).as_str(), None)
    }
}

impl From<FromHexError> for PassError {
    fn from(err: FromHexError) -> Self {
        PassError::runtime(format!("hex conversion failed {:?}", err).as_str(), None)
    }
}

impl From<Utf8Error> for PassError {
    fn from(err: Utf8Error) -> Self {
        PassError::runtime(format!("utf failed {:?}", err).as_str(), None)
    }
}

impl From<reqwest::Error> for PassError {
    fn from(err: reqwest::Error) -> Self {
        PassError::runtime(format!("http request failed {:?}", err).as_str(), None)
    }
}

impl Display for PassError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PassError::Database {
                message,
                reason_code,
                retryable,
            } => {
                write!(f, "{} {:?} {}", message, reason_code, retryable)
            }
            PassError::DuplicateKey { message } => {
                write!(f, "{}", message)
            }
            PassError::NotFound { message } => {
                write!(f, "{}", message)
            }
            PassError::CurrentlyUnavailable {
                message,
                reason_code,
                retryable,
            } => {
                write!(f, "{} {:?} {}", message, reason_code, retryable)
            }
            PassError::Validation {
                message,
                reason_code,
            } => {
                write!(f, "{} {:?}", message, reason_code)
            }
            PassError::Serialization { message } => {
                write!(f, "{}", message)
            }
            PassError::Crypto { message } => {
                write!(f, "{}", message)
            }
            PassError::Authentication { message } => {
                write!(f, "{}", message)
            }
            PassError::Authorization { message } => {
                write!(f, "{}", message)
            }
            PassError::WeakPassword { message } => {
                write!(f, "{}", message)
            }
            PassError::Runtime {
                message,
                reason_code,
            } => {
                write!(f, "{} {:?}", message, reason_code)
            }
        }
    }
}

impl Error for PassError {}
