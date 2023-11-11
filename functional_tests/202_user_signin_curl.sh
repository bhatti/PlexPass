#!/bin/bash -e
source env.sh
#curl -v -k https://localhost:8443/api/v1/auth/signin --header "Content-Type: application/json; charset=UTF-8" -d '{"username": "david", "master_password": "Goose$ali@dog.us$Goat551"}'  > /tmp/202.out 2>&1
curl -v -k https://localhost:8443/api/v1/auth/signin --header "Content-Type: application/json; charset=UTF-8" -d '{"username": "bob@cat.us", "master_password": "Goose$bob@cat.us$Goat551"}'  > /tmp/202.out 2>&1
export AUTH_TOKEN=`cat /tmp/202.out|grep access_token|awk '{print $3}'`
export USER_ID=`cat /tmp/202.out|grep user_id| jq '.user_id'|sed "s/\"//g"`
rm /tmp/202.out

#< HTTP/2 200
#< content-length: 50
#< content-type: application/json
#< access_token: eyJ0eXA***
#< vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
#< date: Tue, 07 Nov 2023 20:19:42 GMT
#<
#* Connection #0 to host localhost left intact
#{"user_id":"d8cbe32e-***"}%
