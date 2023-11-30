source env.sh
../target/release/plexpass -j true -d ../PlexPassData --master-username eddie --master-password Cru5h_rfIt:v_Bk create-user || exit 0
../target/release/plexpass -j true -d ../PlexPassData --master-username charlie --master-password Cru5h_rfIt:v_Bk create-user || exit 0
