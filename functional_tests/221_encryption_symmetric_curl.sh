#!/bin/bash -e

source 202_user_signin_curl.sh


keys=`./219_encryption_generate_keys_curl.sh`

prv=`echo $keys|jq '.secret_key'|sed "s/\"//g"`

curl -v -k --http2 --sslv2 -X POST https://localhost:8443/api/v1/encryption/symmetric_encrypt/$prv --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" --data-binary "@accounts.csv" > enc_accounts.csv

curl -v -k --http2 --sslv2 -X POST https://localhost:8443/api/v1/encryption/symmetric_decrypt/$prv --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" --data-binary "@enc_accounts.csv" > enc_accounts.csv

diff accounts.csv enc_accounts.csv
