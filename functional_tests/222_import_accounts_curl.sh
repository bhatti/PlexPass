#!/bin/bash -e

source 202_user_signin_curl.sh

vault_id=`./207_vault_all_curl.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`

curl -v -k --http2 --sslv2 -X POST https://localhost:8443/api/v1//vaults/$vault_id/import --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" --data-binary "@accounts.csv" -d '{}'

curl -v -k --http2 --sslv2 -X POST "https://localhost:8443/api/v1//vaults/$vault_id/export" --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" -d '{"password": "123"}' > enc_accounts.csv

curl -v -k --http2 --sslv2 -X POST https://localhost:8443/api/v1//vaults/$vault_id/import --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" --data-binary "@enc_accounts.csv" -d '{"password": "123"}'

