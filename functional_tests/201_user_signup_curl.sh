source env.sh
curl -v -k https://localhost:8443/api/v1/auth/signup --header "Content-Type: application/json; charset=UTF-8" -d '{"username": "david", "master_password": "Goose$ali@dog.us$Goat551", "email": "dave@buster.com", "name": "Dave"}' 
curl -v -k https://localhost:8443/api/v1/auth/signup --header "Content-Type: application/json; charset=UTF-8" -d '{"username": "edward", "master_password": "Goose$ali@dog.us$Goat551", "email": "ed@wen.com", "name": "Eddie"}' 

#< HTTP/2 200
#< content-length: 50
#< content-type: application/json
#< access_token: eyJ0eXA**
#< vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
#< date: Tue, 07 Nov 2023 20:17:49 GMT
#<
#* Connection #0 to host localhost left intact
#{"user_id":"d8cbe32e-***"}%
