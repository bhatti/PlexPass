#!/bin/bash -e
source env.sh
vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk analyze-vault-passwords --vault-id $vault_id
#{"total_accounts":35,"count_strong_passwords":1,"count_moderate_passwords":20,"count_weak_passwords":14,"count_healthy_passwords":1,"count_compromised":32,"count_reused":29,"count_similar_to_other_passwords":22,"count_similar_to_past_passwords":0}
