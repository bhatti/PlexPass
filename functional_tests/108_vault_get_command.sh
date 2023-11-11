#!/bin/bash -e
source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`
../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vault --vault-id $vault_id

exit
{
  "vault_id": "44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa",
  "version": 0,
  "owner_user_id": "c81446b7-8de4-41d7-b5a7-36d4075777bc",
  "title": "Identity",
  "kind": "Logins",
  "icon": null,
  "entries": null,
  "analysis": null,
  "analyzed_at": null,
  "created_at": "2023-11-08T03:45:44.163762",
  "updated_at": "2023-11-08T03:45:44.163762"
}
