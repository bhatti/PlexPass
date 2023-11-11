#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk password-strength --password mypassword
#{"strength":"MODERATE","entropy":42.303957463269825,"uppercase":0,"lowercase":10,"digits":0,"special_chars":0,"length":10}
