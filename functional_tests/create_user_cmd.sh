clear
cargo build --release
export CERT_FILE=config/cert-pass.pem
export KEY_FILE=config/key-pass.pem
export HSM_PROVIDER=EncryptedFile
./target/release/plexpass -j true  --master-username charlie --master-password Cru5h_rfIt:v_Bk create-user
#{"user_id":"133f5784-37d4-480a-8d9c-2aef8ebdb48a","version":0,"username":"charlie","roles":{"mask":0},"name":null,"email":null,"locale":null,"light_mode":null,"icon":null,"attributes":[],"created_at":"2023-10-26T03:49:08.938354","updated_at":"2023-10-26T03:49:08.938357"}

id=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user |jq '.user_id'| sed "s/\"//g"`
echo id $id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk delete-user --user-id $id
version=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user|jq '.version'`
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk update-user --locale en-US --version $version
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user

./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-vault --title myvault

vault_id=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-vaults | jq '.[].vault_id'|head -1 | sed "s/\"//g"`
version=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-vault --vault-id $vault_id|jq '.version'`
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk update-vault --vault-id $vault_id --title new-title --version $version
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-vault --vault-id $vault_id

./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label Youtube --username youlogin --password youpass --url https://www.youtube.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label Amazon --username amazonlogin --password amazonpass --url https://www.amazon.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label BoA --username boalogin --password boapass --url https://www.boa.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label ATT --username attlogin --password attpass --url https://www.att.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label Twitter --username twitterlogin --password twitterpass --url https://www.twitter.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label Allstate --username allstatelogin --password allstatepass --url https://www.allstate.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label microsoft --username microsoftlogin --password microsoftpass --url https://www.microsoft.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label netflix --username netflixlogin --password netflixpass --url https://www.netflix.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label facebook --username facebooklogin --password facebookpass --url https://www.facebook.com --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label twitch --username twitchlogin --password twitchpass --url https://www.twitch.tv --notes mynote --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label "My note1" --notes "My secure note1" --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label "My note2" --notes "My secure note2" --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label "My note3" --notes "My secure note3" --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label "My note4" --notes "My secure note4" --vault-id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-account --label "My note5" --notes "My secure note5" --vault-id $vault_id
echo vault id $vault_id
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-accounts --vault-id $vault_id|jq '.'
account_id=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-accounts --vault-id $vault_id | jq '.[].account_id'|head -1 | sed "s/\"//g"`
version=`./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-account --account-id $account_id|jq '.details.version'`
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk update-account --account-id $account_id --vault-id $vault_id --email "myemail@io" --username "myuser" --password "mypass"
./target/release/plexpass --json-output true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-account --account-id $account_id
