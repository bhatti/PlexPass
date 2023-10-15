# PlexPass
Secured Family-friendly Password Manager (WIP)

The PlexPass uses https://diesel.rs/ library for ORM when using relational databases. It uses Sqlite by default, but
you can customize it to any supported database.

## Setup

### Relational Database
Install diesel cli:
```shell
brew install libpq
brew link --force libpq
PQ_LIB_DIR="$(brew --prefix libpq)/lib"
cargo install diesel_cli --no-default-features --features sqlite
```

Set URL to relational database
```shell
export DATABASE_URL=postgres://<postgres_username>:<postgres_password>@<postgres_host>:<postgres_port>/school
```

Perform MIGRATIONS. At this step Rust schema is also automatically generated and printed to the file defined in `diesel.toml`
```shell
diesel setup
diesel migration run
```

Put database in vanilla state
```shell
diesel migration redo
```


## Execute

Run PlexPass manager
```shell
cargo run --
```