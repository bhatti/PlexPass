#!/bin/bash -e
source env.sh

curl -v -k https://localhost:8443/api/v1/auth/signin --header "Content-Type: application/json; charset=UTF-8" -d '{"username": "edward", "master_password": "Goose$ali@dog.us$Goat551"}'  > /tmp/202.out 2>&1
export AUTH_TOKEN=`cat /tmp/202.out|grep access_token|awk '{print $3}'`
export USER_ID=`cat /tmp/202.out|grep user_id| jq '.user_id'|sed "s/\"//g"`
rm /tmp/202.out

curl -v -k --http1.1 -X DELETE https://localhost:8443/api/v1/users/$USER_ID --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" 
