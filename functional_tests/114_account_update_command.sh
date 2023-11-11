#!/bin/bash -e
source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./112_account_all_command.sh|jq '.[].details.account_id'|sed "s/\"//g"|head -1`
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk update-account --vault-id $vault_id --account-id $account_id --kind Logins --label "Prag prog" --username samuel1 --email "$RANDOM.samuel@gmio.com" --password "sam123" --icon stuff --notes "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est."




