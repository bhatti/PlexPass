source env.sh

vault_id=`../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk get-vaults|jq '.[].vault_id'|head -1|sed "s/\"//g"`

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk create-account --vault-id $vault_id --kind Logins --label "Oreilly's Books `date`" --username jackson --email "$RANDOM.jack@io.com" --password "jack123" --notes "Lorem ipsum dolor sit amet" || exit 0

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk create-account --vault-id $vault_id --kind Logins --label "Prag prog `date`" --username samuel --email "$RANDOM.samuel@io.com" --password "sam123" --otp "JBSWY3DPEHPK3PXP" --notes "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est." || exit 0
