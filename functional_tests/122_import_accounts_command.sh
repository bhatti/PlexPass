#!/bin/bash -e
source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk import-accounts --vault-id $vault_id --in-path accounts.csv
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk export-accounts --vault-id $vault_id --password 7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe --out-path enc.out
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk import-accounts --vault-id $vault_id --password 7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe --in-path enc.out

