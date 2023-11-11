#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk email-compromised --email login@mail.com || exit 0
#could not check password: Validation { message: "could not find api key for HIBP", reason_code: None }
