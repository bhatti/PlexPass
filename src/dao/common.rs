use std::convert::From;
use std::path::Path;
use std::time::Duration;

use crate::domain::error::PassError;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::result::DatabaseErrorKind;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationError, MigrationHarness};

use crate::domain::models::{PassConfig, PassResult};

#[derive(Debug)]
pub struct ConnectionOptions {
    pub enable_wal: bool,
    pub enable_foreign_keys: bool,
    pub busy_timeout: Option<Duration>,
}

impl r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for ConnectionOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        (|| {
            if self.enable_wal {
                conn.batch_execute("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
            }
            if self.enable_foreign_keys {
                conn.batch_execute("PRAGMA foreign_keys = ON;")?;
            }
            if let Some(d) = self.busy_timeout {
                conn.batch_execute(&format!("PRAGMA busy_timeout = {};", d.as_millis()))?;
            }
            Ok(())
        })()
        .map_err(diesel::r2d2::Error::QueryError)
    }
}

fn run_migrations(mut conn: SqliteConnection) -> PassResult<()> {
    //let MIGRATIONS = FileBasedMigrations::find_migrations_directory()?;
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
    log::info!("running MIGRATIONS...");
    match conn.run_pending_migrations(MIGRATIONS) {
        Ok(_) => {}
        Err(err) => {
            return Err(PassError::database(err.to_string().as_str(), None, true));
        }
    };
    match conn.begin_test_transaction() {
        Ok(_) => {}
        Err(err) => {
            return Err(PassError::database(err.to_string().as_str(), None, true));
        }
    };
    Ok(())
}

pub(crate) fn build_sqlite_pool(
    config: &PassConfig,
) -> PassResult<Pool<ConnectionManager<SqliteConnection>>> {
    log::debug!("building sqlite connection pool for {:?}", config);
    let db_url = config.database_file();
    let manager = ConnectionManager::<SqliteConnection>::new(&db_url);

    if !Path::new(db_url.as_str()).exists() {
        log::info!("running sqlite migrations for {}", &db_url);
        let conn = build_sqlite_connection(&db_url).unwrap();
        run_migrations(conn)?;
    }

    match Pool::builder()
        .max_size(config.max_pool_size.clone())
        .connection_customizer(Box::new(ConnectionOptions {
            enable_wal: true,
            enable_foreign_keys: true,
            busy_timeout: Some(Duration::from_secs(60)),
        }))
        .test_on_check_out(true)
        .build(manager)
    {
        Ok(pool) => Ok(pool),
        Err(err) => Err(PassError::database(err.to_string().as_str(), None, true)),
    }
}

fn build_sqlite_connection(database_url: &str) -> ConnectionResult<SqliteConnection> {
    SqliteConnection::establish(database_url)
}

impl From<MigrationError> for PassError {
    fn from(err: MigrationError) -> Self {
        PassError::database(
            format!("rdb database migration error {:?}", err).as_str(),
            None,
            false,
        )
    }
}

impl From<diesel::result::Error> for PassError {
    fn from(err: diesel::result::Error) -> Self {
        let (retryable, opt_reason) = retryable_db_error(&err);
        if retryable {
            return PassError::unavailable(
                format!("rdb database error {:?} {:?}", err, opt_reason).as_str(),
                opt_reason,
                true,
            );
        }
        if let Some(reason) = opt_reason.clone() {
            let lower_reason = reason.to_lowercase();
            if lower_reason.contains("notfound") {
                return PassError::not_found(
                    format!("not found error {:?} {:?}", err, reason).as_str(),
                );
            } else if lower_reason.contains("unique") {
                return PassError::duplicate_key(
                    format!("duplicate key error {:?} {:?}", err, reason).as_str(),
                );
            }
        }
        PassError::database(
            format!("rdb database error {:?} {:?}", err, opt_reason).as_str(),
            opt_reason,
            false,
        )
    }
}

pub(crate) fn retryable_db_error(err: &diesel::result::Error) -> (bool, Option<String>) {
    match err {
        diesel::result::Error::InvalidCString(_) => (false, Some("InvalidCString".into())),
        diesel::result::Error::DatabaseError(kind, _) => match kind {
            DatabaseErrorKind::UniqueViolation => (false, Some("UniqueViolation".into())),
            DatabaseErrorKind::ForeignKeyViolation => (false, Some("ForeignKeyViolation".into())),
            DatabaseErrorKind::UnableToSendCommand => (true, Some("UnableToSendCommand".into())),
            DatabaseErrorKind::SerializationFailure => (false, Some("SerializationFailure".into())),
            DatabaseErrorKind::ReadOnlyTransaction => (false, Some("ReadOnlyTransaction".into())),
            DatabaseErrorKind::NotNullViolation => (false, Some("NotNullViolation".into())),
            DatabaseErrorKind::CheckViolation => (false, Some("CheckViolation".into())),
            DatabaseErrorKind::ClosedConnection => (true, Some("ClosedConnection".into())),
            DatabaseErrorKind::Unknown => (true, Some("Unknown".into())),
            _ => (true, None),
        },
        diesel::result::Error::NotFound => (false, Some("NotFound".into())),
        diesel::result::Error::QueryBuilderError(_) => (false, Some("QueryBuilderError".into())),
        diesel::result::Error::DeserializationError(_) => {
            (false, Some("DeserializationError".into()))
        }
        diesel::result::Error::SerializationError(_) => (false, Some("SerializationError".into())),
        diesel::result::Error::RollbackErrorOnCommit { .. } => {
            (false, Some("RollbackErrorOnCommit".into()))
        }
        diesel::result::Error::RollbackTransaction => (false, Some("RollbackTransaction".into())),
        diesel::result::Error::AlreadyInTransaction => (false, Some("AlreadyInTransaction".into())),
        diesel::result::Error::NotInTransaction => (false, Some("NotInTransaction".into())),
        diesel::result::Error::BrokenTransactionManager => {
            (false, Some("BrokenTransactionManager".into()))
        }
        _ => (true, None),
    }
}
