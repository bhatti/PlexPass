#!/bin/bash -e
source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`
clear

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk share-vault --vault-id $vault_id --target-username charlie
#../target/release/plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk unshare-vault --vault-id $vault_id --target-username charlie
