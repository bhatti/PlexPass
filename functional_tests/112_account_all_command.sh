#!/bin/bash -e
source env.sh

#vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -2|tail -1|sed "s/\"//g"`
vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-accounts --vault-id $vault_id --q "jackson"


