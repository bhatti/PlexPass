#!/bin/bash -e

account_id=`./212_account_all_curl.sh|jq '.accounts[].account_id'|head -1|sed "s/\"//g"`

source 202_user_signin_curl.sh
echo xxxxxxxxxx account_id $account_id

curl -v -k --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" https://localhost:8443/api/v1/vaults/111/accounts/$account_id
#curl -v -k --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" https://localhost:8443/api/v1/otp/generate -d '{"otp_secret": "JBSWY3DPEHPK3PXP"}'
