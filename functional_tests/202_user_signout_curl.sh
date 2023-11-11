#!/bin/bash -e
source 202_user_signin_curl.sh
curl -X POST -k https://localhost:8443/api/v1/auth/signout --header "Content-Type: application/json; charset=UTF-8"  --header "Authorization: Bearer $AUTH_TOKEN"
