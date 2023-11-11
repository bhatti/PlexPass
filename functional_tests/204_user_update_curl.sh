#!/bin/bash -e
source 202_user_signin_curl.sh

echo ""
curl -v -k --http1.1 -X PUT https://localhost:8443/api/v1/users/$USER_ID --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" -d '{"username": "david", "icon": "stuff", "email": "dave@buster.com", "name": "Dave Budd"}' 

