#!/bin/bash -e

source 202_user_signin_curl.sh

curl -v -k --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" https://localhost:8443/api/v1/password/mypassword/compromised
