#!/bin/bash -e
source env.sh

vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`

CWD=`pwd`

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk import-accounts --vault-id $vault_id --in-path /files/accounts.csv

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk export-accounts --vault-id $vault_id --password 7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe --out-path /files/enc_accounts.csv

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk import-accounts --vault-id $vault_id --in-path /files/enc_accounts.csv --password 7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe

diff accounts.csv enc_accounts.csv
