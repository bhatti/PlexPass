#!/bin/bash -e
source env.sh

keys=`./319_encryption_generate_keys_docker.sh`

pub=`echo $keys|jq '.public_key'|sed "s/\"//g"`
prv=`echo $keys|jq '.secret_key'|sed "s/\"//g"`

CWD=`pwd`

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk asymmetric-encrypt --public-key $pub --in-path /files/accounts.csv --out-path /files/enc_accounts.csv
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk asymmetric-decrypt --secret-key $prv --in-path /files/enc_accounts.csv --out-path /files/enc.out

diff accounts.csv enc.out
