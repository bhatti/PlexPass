#!/bin/bash -e
source env.sh

keys=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-private-public-keys`

prv=`echo $keys|jq '.secret_key'|sed "s/\"//g"`


../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk symmetric-encrypt --secret-key $prv --in-path accounts.csv --out-path enc_accounts.csv
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk symmetric-decrypt --secret-key $prv --in-path enc_accounts.csv --out-path enc_accounts.csv

diff accounts.csv enc_accounts.csv
