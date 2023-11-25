#!/bin/bash -e
source env.sh
#export RUST_LOG="actix_web=trace"
#export RUST_LOG="actix_web=trace"
mkdir -p ../PlexPassData
cp ../config/* ../PlexPassData
cd .. && cargo build --release && ./target/release/plexpass server
