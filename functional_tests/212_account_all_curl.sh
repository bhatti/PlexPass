#!/bin/bash -e

vault_id=`./207_vault_all_curl.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
source 202_user_signin_curl.sh

curl -v -k "https://localhost:8443/api/v1/vaults/$vault_id/accounts?q=allstat" --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" 
