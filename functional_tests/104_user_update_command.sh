#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user
../target/release/plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk update-user --name "Charles" --email "charlie@mail.com"
