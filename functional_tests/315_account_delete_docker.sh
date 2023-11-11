#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./312_acount_all_docker.sh|jq '.[].details.account_id'|sed "s/\"//g"|head -1`
source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk delete-account --account-id $account_id 


