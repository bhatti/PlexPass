source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./112_account_all_command.sh|jq '.[].account_id'|sed "s/\"//g"|head -1`

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk create-category --name "Gumball" || exit 0
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk create-category --name "Gumball baloons" || exit 0




