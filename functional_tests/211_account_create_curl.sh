#!/bin/bash -e

vault_id=`./207_vault_all_curl.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
source 202_user_signin_curl.sh

curl -v -k -X POST https://localhost:8443/api/v1/vaults --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" -d '{"vault_id": "xxx", "username": "harry", "password": "harry", "url": "https://www.homedepot.com", "email": "harry@bitvault.com"}'