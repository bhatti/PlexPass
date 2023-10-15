use std::env;
use std::path::PathBuf;

use actix_files::NamedFile;
use actix_web::HttpRequest;

pub(crate) async fn serve_wasm(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let cwd = env::current_dir();
    log::warn!(
        "---cwd {:?}, path {:?}",
        cwd,
        req.match_info().query("filename")
    );
    let fp: PathBuf = req.match_info().query("filename").parse().unwrap();
    let path = PathBuf::new().join("./wasm/pkg").join(fp);
    log::warn!("cwd {:?}, path {:?}", cwd, path);
    Ok(NamedFile::open(path)?)
}
