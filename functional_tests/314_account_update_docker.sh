#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./312_acount_all_docker.sh|jq '.[].details.account_id'|sed "s/\"//g"|head -1`
source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk update-account --account-id $account_id --vault-id $vault_id --icon stuff --kind Logins --label "Prag prog" --username samuel --email samuel@io.com --password "sam123" --notes "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est."


