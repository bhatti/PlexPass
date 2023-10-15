use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug, Clone)]
pub enum CommandActions {
    Acquire {
        /// key of account or vault to acquire
        #[arg(short, long)]
        key: String,

        // How long the lease for the lock is (in seconds)
        #[arg(short, long, default_value_t = 15)]
        lease: i64,

        // If this requires a vault, then specify vault size
        #[arg(short, long)]
        vault_max_size: Option<i32>,

        // The data to be stored alongside the lock (can be empty)
        #[arg(short, long)]
        data: Option<String>,
    },
    Heartbeat {
        /// key of account to renew lease
        #[arg(short, long)]
        key: String,

        // record version of the lock in database. This is what tells the lock client when the lock is stale.
        #[arg(short, long)]
        version: String,

        // How long the lease for the lock is (in seconds)
        #[arg(short, long, default_value_t = 15)]
        lease: i64,

        // If this requires a vault previously created
        #[arg(short, long)]
        vault_key: Option<String>,

        // The data to be stored alongside the lock (can be empty)
        #[arg(short, long)]
        data: Option<String>,
    },
    Release {
        /// key of account to release
        #[arg(short, long)]
        key: String,

        // record version of the lock in database. This is what tells the lock client when the lock is stale.
        #[arg(short, long)]
        version: String,

        // If this requires a vault previously created
        #[arg(short, long)]
        vault_key: Option<String>,

        // The data to be stored alongside the lock (can be empty)
        #[arg(short, long)]
        data: Option<String>,
    },
    GetAccount {
        /// key of account to retrieve
        #[arg(short, long)]
        key: String,
    },
    DeleteAccount {
        /// key of account to delete
        #[arg(short, long)]
        key: String,

        // record version of the lock in database. This is what tells the lock client when the lock is stale.
        #[arg(short, long)]
        version: String,

        // If this requires a vault previously created
        #[arg(short, long)]
        vault_key: Option<String>,
    },
    CreateAccount {
        /// key of vault to create
        #[arg(short, long)]
        key: String,

        // How long the lease for the lock is (in seconds)
        #[arg(short, long, default_value_t = 15)]
        lease: i64,

        // The data to be stored alongside the lock (can be empty)
        #[arg(short, long)]
        data: Option<String>,
    },
    CreateVault {
        /// key of vault to create
        #[arg(short, long)]
        key: String,

        // The number of locks in vaults
        #[arg(short, long)]
        max_size: i64,

        // How long the lease for the lock is (in seconds)
        #[arg(short, long, default_value_t = 15)]
        lease: i64,
    },
    GetVault {
        /// key of vault to retrieve
        #[arg(short, long)]
        key: String,
    },
    DeleteVault {
        /// key of vault to delete
        #[arg(short, long)]
        key: String,

        // record version of the lock in database. This is what tells the lock client when the lock is stale.
        #[arg(short, long)]
        version: String,
    },
    GetVaultaccounts {
        /// key of vault for retrieving accounts
        #[arg(short, long)]
        key: String,
    },
}

/// accounts and Vaults based Distributed Locks with databases.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(next_line_help = true)]
pub struct Args {
    /// Action to perform
    #[command(subcommand)]
    pub action: CommandActions,

    /// tentant-id for the database
    #[arg(short, long, default_value = "local-host-name")]
    pub tenant: String,

    /// fair vault lock
    #[arg(short, long, default_value = "false")]
    pub fair_vault: Option<bool>,

    /// json output of result from action
    #[arg(short, long, default_value = "false")]
    pub json_output: Option<bool>,

    /// Sets a data directory
    #[arg(short, long, value_name = "DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Sets a data directory
    #[arg(short, long, value_name = "CRYPTO_ALG")]
    pub crypto_algorithm: String,

    /// Sets a data directory
    #[arg(short, long, value_name = "HASH_ALG")]
    pub hash_algorithm: String,
}
