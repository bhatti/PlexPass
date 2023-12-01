include!(concat!(env!("OUT_DIR"), "/version_info.rs"));

extern crate diesel;
extern crate diesel_migrations;
extern crate dotenv;
extern crate lazy_static;

pub mod command;
pub mod controller;
pub mod domain;
pub mod store;
mod auth;
mod background;
mod crypto;
mod dao;
mod hibp;
mod service;
mod utils;
mod locales;
mod csv;


