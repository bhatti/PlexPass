#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk asymmetric-user-encrypt --target-username eddie --in-path accounts.csv --out-path enc_accounts.csv
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk asymmetric-user-decrypt --in-path enc_accounts.csv --out-path enc_accounts.csv

diff accounts.csv enc_accounts.csv
