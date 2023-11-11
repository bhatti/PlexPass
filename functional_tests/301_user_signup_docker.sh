source env.sh
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username charlie --master-password Cru5h_rfIt:v_Bk create-user || exit 0
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank --master-password Cru5h_rfIt:v_Bk create-user || exit 0

# {"user_id":"d163a4bb-6767-4f4c-845f-86874a04fe20","version":0,"username":"charlie","roles":{"mask":0},"name":null,"email":null,"locale":null,"light_mode":null,"icon":null,"attributes":[],"created_at":"2023-11-07T20:30:32.023694776","updated_at":"2023-11-07T20:30:32.023695205"}
#docker run -it --entrypoint /bin/bash -p 8080:8080 -p 8443:8443 -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
