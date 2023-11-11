#!/bin/bash -e
source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk get-user

#{
#  "user_id": "d163a4bb-6767-4f4c-845f-86874a04fe20",
#  "version": 0,
#  "username": "charlie",
#  "roles": {
#    "mask": 0
#  },
#  "name": null,
#  "email": null,
#  "locale": null,
#  "light_mode": null,
#  "icon": null,
#  "attributes": [],
#  "created_at": "2023-11-07T20:30:32.063323960",
#  "updated_at": "2023-11-07T20:30:32.063324497"
#}
