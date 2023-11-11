#!/bin/bash -e
source env.sh
version=`./303_user_get_docker.sh|jq '.version'`
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk update-user --name "Charles" --email "charlie@mail.com"
