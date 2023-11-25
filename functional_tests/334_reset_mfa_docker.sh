#!/bin/bash -e
source env.sh

otp=`docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true generate-otp --otp-secret DA6ZIW3ZIR7H32I2PX5L76A4S5TVCEDEDLUMFS3WKEZEULISS6MA|jq '.otp_code'`

docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true ----master-username charlie --master-password Cru5h_rfIt:v_Bk  --otp-code $otp reset-multi-factor-authentication --recovery-code DiUpaIEOibSy
