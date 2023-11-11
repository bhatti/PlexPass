#!/bin/bash -e
vault_id=`./307_vault_all_docker.sh|jq '.[].vault_id'|head -1|sed "s/\"//g"`
source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk create-account --vault-id $vault_id --kind Logins --label "Prag prog" --username samuel --email samuel@io.com --password "sam123" --notes "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est."

exit
[
  {
    "account_id": "afe415b6-21bf-46e1-b768-b3e31e216031",
    "version": 0,
    "kind": "Login",
    "label": "Prag prog",
    "favorite": false,
    "risk": "Unknown",
    "description": null,
    "username": "samuel",
    "email": "samuel@io.com",
    "url": null,
    "category": null,
    "tags": [],
    "favicon": null,
    "icon": null,
    "advisories": {},
    "renew_interval_days": null,
    "expires_at": null,
    "credentials_updated_at": "2023-11-09T00:52:32.066647445",
    "analyzed_at": null
  }
]
