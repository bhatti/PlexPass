#!/bin/bash -e
source env.sh

keys=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-private-public-keys`

pub=`echo $keys|jq '.public_key'|sed "s/\"//g"`
prv=`echo $keys|jq '.secret_key'|sed "s/\"//g"`


../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk asymmetric-encrypt --public-key $pub --in-path accounts.csv --out-path enc_accounts.csv
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk asymmetric-decrypt --secret-key $prv --in-path enc_accounts.csv --out-path enc.out

diff accounts.csv enc.out
