#!/bin/bash -e
source env.sh

account_id=`./112_account_all_command.sh|jq '.[].account_id'|sed "s/\"//g"|head -1`
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-account-otp --account-id $account_id
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-account-otp --otp-secret "JBSWY3DPEHPK3PXP"
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-user-otp
