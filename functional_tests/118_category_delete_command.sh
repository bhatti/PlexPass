#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk delete-category --name "Gumball baloons" || exit 0




