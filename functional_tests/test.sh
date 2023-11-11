#!/bin/bash -ex

./01_user_tests.py
./02_vault_tests.py
./03_account_test.py
./04_password_test.py
./05_encryption_test.py
./06_import_export_test.py
./07_share_vault_test.py
./08_category_test.py
./09_audit_logs_test.py
./101_user_signup_command.sh
./102_user_signin_command.sh
./103_user_get_command.sh
./104_user_update_command.sh
./105_user_delete_command.sh
./106_vault_create_command.sh
./107_vault_all_command.sh
./108_vault_get_command.sh
./109_vault_update_command.sh
./110_vault_delete_command.sh
./111_account_create_command.sh
./112_account_all_command.sh
./113_account_get_command.sh
./114_account_update_command.sh
./115_account_delete_command.sh
./116_category_create_command.sh
./117_category_get_command.sh
./118_category_delete_command.sh
./119_encryption_generate_keys_command.sh
./120_encryption_asymmetric_command.sh
./121_encryption_symmetric_command.sh
./122_import_accounts_command.sh
./123_password_generate_command.sh
./124_password_compromised_command.sh
./125_password_strength_command.sh
./126_email_compromised_command.sh
./127_analyze_vault_password_command.sh
./128_analyze_all_vaults_password_command.sh
./129_search_usernames_command.sh
./130_vault_share_command.sh
./131_account_share_command.sh

exit
./201_user_signup_curl.sh
./202_user_signin_curl.sh
./202_user_signout_curl.sh
./203_user_get_curl.sh
./204_user_update_curl.sh
./205_user_delete_curl.sh
./206_vault_create_curl.sh
./207_vault_all_curl.sh
./208_vault_get_curl.sh
./209_vault_update_curl.sh
./210_vault_delete_curl.sh
./211_account_create_curl.sh
./212_account_all_curl.sh
./213_account_get_curl.sh
./214_account_update_curl.sh
./215_account_delete_curl.sh
./216_category_create_curl.sh
./217_category_get_curl.sh
./218_category_delete_curl.sh


./301_user_signup_docker.sh
./302_user_signin_docker.sh
./303_user_get_docker.sh
./304_user_update_docker.sh
./305_user_delete_docker.sh
./306_vault_create_docker.sh
./307_vault_all_docker.sh
./308_vault_get_docker.sh
./309_vault_update_docker.sh
./310_vault_delete_docker.sh
./311_account_create_docker.sh
./312_acount_all_docker.sh
./313_account_get_docker.sh
./314_account_update_docker.sh
./315_account_delete_docker.sh
./316_category_create_docker.sh
./317_category_get_docker.sh
./318_category_delete_docker.sh

rm enc.out enc_accounts.csv