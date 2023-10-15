use actix_web::http::header;
use actix_web::{get, web, Error, HttpResponse};
use prometheus::{Encoder, TextEncoder};

// #[get("/api/v1/metrics")]
// pub async fn metrics() -> Result<HttpResponse, Error> {
//     let encoder = TextEncoder::new();
//     let mut buffer = vec![];
//     match encoder.encode(&prometheus::gather(), &mut buffer) {
//         Ok(_) => {
//             let response = String::from_utf8(buffer.clone()).unwrap_or("no metrics".into());
//             buffer.clear();
//             Ok(HttpResponse::Ok()
//                 .insert_header(header::ContentType("text/plain"))
//                 .body(response))
//         }
//         Err(err) => Err(err),
//     }
// }
