// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (account_id) {
        account_id -> Text,
        version -> BigInt,
        vault_id -> Text,
        archived_version -> Nullable<BigInt>,
        salt -> Text,
        nonce -> Text,
        encrypted_value -> Text,
        value_hash -> Text,
        credentials_updated_at -> Timestamp,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    acls (acl_id) {
        acl_id -> Text,
        version -> BigInt,
        acl_user_id -> Text,
        resource_type -> Text,
        resource_id -> Text,
        permissions -> BigInt,
        scope -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    archived_accounts (account_id, version) {
        account_id -> Text,
        version -> BigInt,
        vault_id -> Text,
        crypto_key_id -> Text,
        salt -> Text,
        nonce -> Text,
        encrypted_value -> Text,
        value_hash -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    audit_records (audit_id) {
        audit_id -> Text,
        user_id -> Text,
        kind -> Text,
        ip_address -> Nullable<Text>,
        context -> Text,
        message -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    crypto_keys (crypto_key_id) {
        crypto_key_id -> Text,
        parent_crypto_key_id -> Text,
        user_id -> Text,
        keyable_id -> Text,
        keyable_type -> Text,
        salt -> Text,
        nonce -> Text,
        public_key -> Text,
        encrypted_private_key -> Text,
        encrypted_symmetric_key -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    login_sessions (login_session_id) {
        login_session_id -> Text,
        user_id -> Text,
        username -> Text,
        roles -> BigInt,
        source -> Nullable<Text>,
        ip_address -> Nullable<Text>,
        mfa_required -> Bool,
        mfa_verified_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        signed_out_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    lookups (lookup_id) {
        lookup_id -> Text,
        version -> BigInt,
        user_id -> Text,
        kind -> Text,
        name -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    messages (message_id) {
        message_id -> Text,
        user_id -> Text,
        specversion -> Text,
        source -> Text,
        kind -> Text,
        flags -> BigInt,
        salt -> Text,
        nonce -> Text,
        encrypted_value -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    settings (setting_id) {
        setting_id -> Text,
        version -> BigInt,
        user_id -> Text,
        kind -> Text,
        name -> Text,
        value -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    users (user_id) {
        user_id -> Text,
        version -> BigInt,
        username -> Text,
        salt -> Text,
        nonce -> Text,
        encrypted_value -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    users_vaults (user_vault_id) {
        user_vault_id -> Text,
        user_id -> Text,
        vault_id -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    vaults (vault_id) {
        vault_id -> Text,
        version -> BigInt,
        owner_user_id -> Text,
        title -> Text,
        kind -> Text,
        salt -> Text,
        nonce -> Text,
        encrypted_value -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::joinable!(accounts -> vaults (vault_id));
diesel::joinable!(acls -> users (acl_user_id));
diesel::joinable!(archived_accounts -> vaults (vault_id));
diesel::joinable!(audit_records -> users (user_id));
diesel::joinable!(crypto_keys -> users (user_id));
diesel::joinable!(login_sessions -> users (user_id));
diesel::joinable!(lookups -> users (user_id));
diesel::joinable!(messages -> users (user_id));
diesel::joinable!(settings -> users (user_id));
diesel::joinable!(users_vaults -> users (user_id));
diesel::joinable!(users_vaults -> vaults (vault_id));
diesel::joinable!(vaults -> users (owner_user_id));

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    acls,
    archived_accounts,
    audit_records,
    crypto_keys,
    login_sessions,
    lookups,
    messages,
    settings,
    users,
    users_vaults,
    vaults,
);
