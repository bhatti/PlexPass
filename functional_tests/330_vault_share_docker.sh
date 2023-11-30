#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|tail -1|sed "s/\"//g"`

source env.sh

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk share-vault --vault-id $vault_id --target-username charlie
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk unshare-vault --vault-id $vault_id --target-username charlie
