#!/bin/bash -e

source 202_user_signin_curl.sh
curl -v -k -X POST https://localhost:8443/api/v1/encryption/generate_keys --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" -d '{}'
