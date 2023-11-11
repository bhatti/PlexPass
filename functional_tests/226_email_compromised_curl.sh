#!/bin/bash -e

source 202_user_signin_curl.sh

curl -v -k --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN" https://localhost:8443/api/v1/emails/email/compromised

#{"strength":"MODERATE","entropy":42.303957463269825,"uppercase":0,"lowercase":10,"digits":0,"special_chars":0,"length":10}%
