source env.sh

../target/release/plexpass -j true --master-username eddie --master-password Cru5h_rfIt:v_Bk delete-user  || exit 0

#failed to delete user: Constraints { message: "user cannot be deleted because it still has vaults and accounts." }
