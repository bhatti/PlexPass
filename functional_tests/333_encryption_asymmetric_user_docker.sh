#!/bin/bash -e
source env.sh

CWD=`pwd`
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk asymmetric-user-encrypt --target-username frank --in-path /files/accounts.csv --out-path /files/enc_accounts.csv
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk asymmetric-user-decrypt --in-path /files/enc_accounts.csv --out-path /files/enc_accounts.csv
diff accounts.csv enc_accounts.csv
