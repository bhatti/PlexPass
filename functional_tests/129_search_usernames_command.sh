#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk search-usernames --q a
