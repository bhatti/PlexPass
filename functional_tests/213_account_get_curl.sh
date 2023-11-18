#!/bin/bash -e

vault_id=`./207_vault_all_curl.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./212_account_all_curl.sh|jq '.accounts[].account_id'|head -1|sed "s/\"//g"`
source 202_user_signin_curl.sh
curl -v -k https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id --header "Content-Type: application/json; charset=UTF-8" --header "Authorization: Bearer $AUTH_TOKEN"

exit
{
  "vault_id": "73b091ba-710b-4de4-8a1e-c185e3ddd304",
  "account_id": "e60321d2-8cad-42b8-b779-4ba5b8911bbf",
  "version": 2,
  "kind": "Login",
  "label": null,
  "favorite": false,
  "risk": "High",
  "risk_bg_color": "background-color: #ff9999;",
  "description": null,
  "username": "bob",
  "password": "Bob#12Books%",
  "email": "bob@bitvault.com",
  "website_url": "books.io",
  "category": null,
  "tags": [],
  "otp": null,
  "icon": null,
  "form_fields": {},
  "notes": null,
  "advisories": {
    "WeakPassword": "The password is MODERATE",
    "CompromisedPassword": "The password is compromised and found in 'Have I been Pwned' database."
  },
  "renew_interval_days": null,
  "expires_at": null,
  "credentials_updated_at": "2023-11-08T02:39:50.656771977",
  "analyzed_at": "2023-11-08T02:40:00.019194124",
  "password_min_uppercase": 1,
  "password_min_lowercase": 1,
  "password_min_digits": 1,
  "password_min_special_chars": 1,
  "password_min_length": 12,
  "password_max_length": 16,
  "created_at": "2023-11-08T02:39:50.657929166",
  "updated_at": "2023-11-08T02:40:00.020244928"
}
