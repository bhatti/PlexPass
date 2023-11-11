#!/bin/bash -e
source env.sh

docker run -p 8080:8080 -p 8443:8443 -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -e CERT_FILE=/data/cert-pass.pem -e KEY_FILE=/data/key-pass.pem -v $PARENT_DIR/PlexPassData:/data plexpass server
 
