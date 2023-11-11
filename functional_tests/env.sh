export DEVICE_PEPPER_KEY=fc66c5561b9bcb5bc8784a292a871c976c88e5291ba98c006a825a112ddca18c
export CERT_FILE=config/cert-pass.pem 
export KEY_FILE=config/key-pass.pem 
export HSM_PROVIDER=EncryptedFile 
export PARENT_DIR="$(dirname `pwd`)"
mkdir -p ../PlexPassData
export DATA_DIR=$PARENT_DIR/PlexPassData
cp ../config/*pem ../PlexPassData
