#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
account_id=`./312_acount_all_docker.sh|jq '.[].details.account_id'|sed "s/\"//g"|head -1`
source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk get-account --account-id $account_id

exit
{
  "details": {
    "account_id": "afe415b6-21bf-46e1-b768-b3e31e216031",
    "version": 0,
    "kind": "Login",
    "label": "Prag prog",
    "favorite": false,
    "risk": "Unknown",
    "description": null,
    "username": "samuel",
    "email": "samuel@io.com",
    "website_url": null,
    "category": null,
    "tags": [],
    "favicon": null,
    "icon": null,
    "advisories": {},
    "renew_interval_days": null,
    "expires_at": null,
    "credentials_updated_at": "2023-11-09T00:52:32.066647445",
    "analyzed_at": null
  },
  "vault_id": "d8368349-ccf2-403b-bf1e-ea393d46862a",
  "archived_version": null,
  "credentials": {
    "password": "sam123",
    "password_sha1": "050989490f1fb728fd7e7866c9af0974d3d32470",
    "form_fields": {},
    "notes": "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est.",
    "otp": null,
    "past_passwords": [],
    "password_policy": {
      "random": false,
      "min_uppercase": 1,
      "min_lowercase": 1,
      "min_digits": 1,
      "min_special_chars": 1,
      "min_length": 12,
      "max_length": 16,
      "exclude_ambiguous": true
    }
  },
  "value_hash": "9d5b12aadd470a1c1def7835103df88bfa33def49bd71284d6b1db8f19c94e6f",
  "created_at": "2023-11-09T00:52:32.067949583",
  "updated_at": "2023-11-09T00:52:32.067949648"
}
