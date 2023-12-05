// build.rs
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use chrono::{Utc, Datelike}; // No need for Timelike

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let build_date = Utc::now();
    let date_string = format!("{}-{:02}-{:02}", build_date.year(), build_date.month(), build_date.day());

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("version_info.rs");
    let mut f = File::create(dest_path).unwrap();

    f.write_all(format!("pub const VERSION: &str = \"{}\";\n", version).as_bytes()).unwrap();
    f.write_all(format!("pub const BUILD_DATE: &str = \"{}\";\n", date_string).as_bytes()).unwrap();
}

