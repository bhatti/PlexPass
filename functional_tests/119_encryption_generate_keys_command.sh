#!/bin/bash -e
source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk generate-private-public-keys

exit
{
  "secret_key": "7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe",
  "public_key": "04339d73ffd49da063d0518ea6661a81e92644c8571df57af3b522a7bcbcd3232f1949d2d60e3ecb096f4a5521453df30420e514c314de8c49cb6d7f5565fe8864"
}


