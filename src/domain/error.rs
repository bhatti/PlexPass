use hex::FromHexError;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use image::ImageError;
use rqrr::DeQRError;
use unic_langid::LanguageIdentifierError;
use webauthn_rs::prelude::WebauthnError;

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
    Constraints {
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
    Import {
        message: String,
        failed_accounts: Vec<String>,
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

    pub fn constraints(message: &str) -> PassError {
        PassError::Constraints {
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

    pub fn import_failed(message: &str, failed_accounts: Vec<String>) -> PassError {
        PassError::Import {
            message: message.into(),
            failed_accounts: failed_accounts.clone(),
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            PassError::Database { retryable, .. } => *retryable,
            PassError::Constraints { .. } => false,
            PassError::DuplicateKey { .. } => false,
            PassError::NotFound { .. } => false,
            PassError::CurrentlyUnavailable { retryable, .. } => *retryable,
            PassError::Validation { .. } => false,
            PassError::Serialization { .. } => false,
            PassError::Crypto { .. } => false,
            PassError::Authentication { .. } => false,
            PassError::Authorization { .. } => false,
            PassError::WeakPassword { .. } => false,
            PassError::Runtime { .. } => false,
            PassError::Import { .. } => false,
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

impl From<LanguageIdentifierError> for PassError {
    fn from(err: LanguageIdentifierError) -> Self {
        PassError::runtime(format!("unicode processing failed {:?}", err).as_str(), None)
    }
}

impl From<csv::Error> for PassError {
    fn from(err: csv::Error) -> Self {
        PassError::runtime(format!("csv parsing failed {:?}", err).as_str(), None)
    }
}

impl From<ParseIntError> for PassError {
    fn from(err: ParseIntError) -> Self {
        PassError::runtime(format!("int parsing failed {:?}", err).as_str(), None)
    }
}

impl From<ImageError> for PassError {
    fn from(err: ImageError) -> Self {
        PassError::runtime(format!("image encoding failed {:?}", err).as_str(), None)
    }
}

impl From<DeQRError> for PassError {
    fn from(err: DeQRError) -> Self {
        PassError::runtime(format!("qrcode encoding failed {:?}", err).as_str(), None)
    }
}

impl From<url::ParseError> for PassError {
    fn from(err: url::ParseError) -> Self {
        PassError::runtime(format!("url parsing failed {:?}", err).as_str(), None)
    }
}

impl From<String> for PassError {
    fn from(err: String) -> Self {
        PassError::runtime(format!("string error failed {:?}", err).as_str(), None)
    }
}

impl From<WebauthnError> for PassError {
    fn from(err: WebauthnError) -> Self {
        PassError::runtime(format!("webauthn error failed {:?}", err).as_str(), None)
    }
}

impl From<uuid::Error> for PassError {
    fn from(err: uuid::Error) -> Self {
        PassError::runtime(format!("uuid error failed {:?}", err).as_str(), None)
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
            PassError::Constraints { message } => {
                write!(f, "{}", message)
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
                if let Some(reason) = reason_code {
                    write!(f, "{} {:?}", message, reason)
                } else {
                    write!(f, "{}", message)
                }
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
            PassError::Import {
                message,
                failed_accounts,
            } => {
                write!(f, "{} {:?}", message, failed_accounts)
            }
        }
    }
}

impl Error for PassError {}
