#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`

source env.sh

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk analyze-vault-passwords --vault-id $vault_id
