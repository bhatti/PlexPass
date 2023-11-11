source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"` 
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk delete-vault --vault-id $vault_id  || exit 0

