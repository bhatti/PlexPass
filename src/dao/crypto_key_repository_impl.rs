use chrono::Utc;
use diesel::prelude::*;

use crate::dao::models::{CryptoKeyEntity};
use crate::dao::schema::crypto_keys;
use crate::dao::schema::crypto_keys::dsl as ck;
use crate::dao::schema::acls::dsl as acl;

use crate::dao::{CryptoKeyRepository, DbConnection};
use crate::domain::error::PassError;
use crate::domain::models::{PassResult};

#[derive(Clone)]
pub(crate) struct CryptoKeyRepositoryImpl {}

impl CryptoKeyRepositoryImpl {
    pub(crate) fn new() -> Self {
        CryptoKeyRepositoryImpl {}
    }
}

impl CryptoKeyRepository for CryptoKeyRepositoryImpl {
    // create crypto_key.
    fn create(
        &self,
        entity: &CryptoKeyEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        diesel::insert_into(crypto_keys::table)
            .values(entity)
            .execute(conn)
    }

    // get crypto_key by id
    fn get(
        &self,
        match_user_id: &str,
        match_keyable_id: &str,
        match_keyable_type: &str,
        conn: &mut DbConnection,
    ) -> Result<CryptoKeyEntity, diesel::result::Error> {
        let mut items: Vec<CryptoKeyEntity> = ck::crypto_keys
            .left_outer_join(
                acl::acls.on(ck::crypto_key_id
                    .eq(acl::resource_id)
                    .or(ck::parent_crypto_key_id.eq(acl::resource_id).and(acl::resource_type.eq("CryptoKeyEntity")))
                    .and(acl::acl_user_id.eq(match_user_id))
                    .and(acl::permissions.gt(0))),
            )
            .filter(
                ck::keyable_id.eq(match_keyable_id)
                    .and(ck::keyable_type.eq(match_keyable_type))
                    .and(
                        ck::user_id
                            .eq(match_user_id)
                            .or(acl::acl_user_id.eq(match_user_id)),
                    ),
            )
            .select(ck::crypto_keys::all_columns())
            .limit(2)
            .load::<CryptoKeyEntity>(conn)?;

        if items.is_empty() {
            log::warn!(
                "could not find crypto key for user {}, keyable {}/{}",
                match_user_id,
                match_keyable_type,
                match_keyable_id
            );
            return Err(diesel::result::Error::NotFound);
        } else if items.len() > 1 {
            let mut filtered = items.into_iter().filter(|i| i.user_id == match_user_id).collect::<Vec<CryptoKeyEntity>>();
            if !filtered.is_empty() {
                return Ok(filtered.remove(0));
            }
            log::warn!(
                "could not match crypto key for user {}, keyable {}/{}",
                match_user_id,
                match_keyable_type,
                match_keyable_id
            );
            return Err(diesel::result::Error::NotFound);
        }
        Ok(items.remove(0))
    }

    // update_private key
    fn update_private_key(
        &self, other_id: &str,
        other_private_key: &str,
        other_nonce: &str,
        conn: &mut DbConnection,
    ) -> PassResult<usize> {
        match diesel::update(
            ck::crypto_keys.filter(ck::crypto_key_id.eq(&other_id)),
        )
            .set((
                ck::encrypted_private_key.eq(other_private_key.to_string()),
                ck::nonce.eq(other_nonce),
                ck::updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(conn)
        {
            Ok(size) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to update private key {}", other_id, ).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // delete an existing crypto_key.
    fn delete(
        &self,
        match_user_id: &str,
        match_keyable_id: &str,
        match_keyable_type: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        conn.transaction(|c| {
            let _ = diesel::delete(
                acl::acls.filter(
                    acl::acl_user_id
                        .eq(match_user_id)
                        .and(acl::resource_id.eq(match_keyable_id))
                        .and(acl::resource_type.eq("CryptoKeyEntity")),
                ),
            )
                .execute(c)?;
            diesel::delete(
                ck::crypto_keys.filter(
                    ck::user_id
                        .eq(match_user_id)
                        .and(ck::keyable_id.eq(match_keyable_id))
                        .and(ck::keyable_type.eq(match_keyable_type)),
                ),
            )
                .execute(c)
        })
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use crate::crypto;
    use crate::dao::{common, CryptoKeyRepository};
    use crate::dao::crypto_key_repository_impl::CryptoKeyRepositoryImpl;
    use crate::dao::factory::{create_acl_repository, create_user_repository};
    use crate::dao::models::{ACLEntity, CryptoKeyEntity, UserContext};
    use crate::domain::models::{PassConfig, User};

    #[tokio::test]
    async fn test_should_create_get_delete_crypto_key() {
        let config = PassConfig::new();
        // GIVEN a user, acl and crypto repository repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let acl_repo = create_acl_repository(&config).await.unwrap();
        let crypto_repo = CryptoKeyRepositoryImpl::new();
        let db_pool = common::build_sqlite_pool(&config).expect("Failed to create db pool");

        let user1 = User::new(&Uuid::new_v4().to_string(), None, None);
        let ctx1 = UserContext::default_new(&user1.username, &user1.user_id,
                                            &hex::encode(crypto::generate_nonce()),
                                            &hex::encode(crypto::generate_secret_key()),
                                            "pass1").unwrap();

        let user2 = User::new(&Uuid::new_v4().to_string(), None, None);
        let ctx2 = UserContext::default_new(&user2.username, &user2.user_id,
                                            &hex::encode(crypto::generate_nonce()),
                                            &hex::encode(crypto::generate_secret_key()),
                                            "pass2").unwrap();

        // WHEN creating the user THEN it should succeed
        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let (crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx1,
            "input",
            &user1.user_id,
            "keyable-id",
            "keyable-type",
            "").unwrap();
        let mut conn = db_pool.get().unwrap();
        let size = crypto_repo.create(&crypto_key, &mut conn).unwrap();
        assert_eq!(1, size);

        let loaded = crypto_repo.get(&user1.user_id,
                                     "keyable-id",
                                     "keyable-type",
                                     &mut conn).unwrap();

        // User 2 should not be able to get crypto key
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());

        // Let's create ACL for access
        {
            let ctx2 = ctx2.as_admin();
            let acl = ACLEntity::for_crypto_key(&ctx2.user_id, &loaded.crypto_key_id);
            let size = acl_repo.create(&ctx2, &acl).await.unwrap();
            assert_eq!(1, size);
        }

        // User 2 should be able to get crypto key
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_ok());


        assert_eq!(crypto_key, loaded);
        let size = crypto_repo.delete(&user1.user_id,
                                      "keyable-id",
                                      "keyable-type",
                                      &mut conn).unwrap();
        assert_eq!(1, size);
        assert!(crypto_repo.get(&user1.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());
    }

    #[tokio::test]
    async fn test_should_create_update_crypto_key() {
        let config = PassConfig::new();
        // GIVEN a user, acl and crypto repository repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let crypto_repo = CryptoKeyRepositoryImpl::new();
        let db_pool = common::build_sqlite_pool(&config).expect("Failed to create db pool");

        let user1 = User::new(&Uuid::new_v4().to_string(), None, None);
        let ctx1 = UserContext::default_new(&user1.username, &user1.user_id,
                                            &hex::encode(crypto::generate_nonce()),
                                            &hex::encode(crypto::generate_secret_key()),
                                            "pass1").unwrap();

        // WHEN creating the user THEN it should succeed
        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());

        let (crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx1,
            "input",
            &user1.user_id,
            "keyable-id",
            "keyable-type",
            "").unwrap();
        let mut conn = db_pool.get().unwrap();
        let size = crypto_repo.create(&crypto_key, &mut conn).unwrap();
        assert_eq!(1, size);

        let size = crypto_repo.update_private_key(
            &crypto_key.crypto_key_id,
            "new-key",
            "new-nonce",
            &mut conn).unwrap();
        assert_eq!(1, size);

        let loaded = crypto_repo.get(&user1.user_id,
                                     "keyable-id",
                                     "keyable-type",
                                     &mut conn).unwrap();
        assert_eq!("new-key", loaded.encrypted_private_key);
        assert_eq!("new-nonce", loaded.nonce);
    }

    #[tokio::test]
    async fn test_should_create_get_delete_crypto_key_with_parent() {
        let config = PassConfig::new();
        // GIVEN a user, acl and crypto repository repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let acl_repo = create_acl_repository(&config).await.unwrap();
        let crypto_repo = CryptoKeyRepositoryImpl::new();
        let db_pool = common::build_sqlite_pool(&config).expect("Failed to create db pool");

        let user1 = User::new(&Uuid::new_v4().to_string(), None, None);
        let ctx1 = UserContext::default_new(&user1.username, &user1.user_id,
                                            &hex::encode(crypto::generate_nonce()),
                                            &hex::encode(crypto::generate_secret_key()),
                                            "pass1").unwrap();

        let user2 = User::new(&Uuid::new_v4().to_string(), None, None);
        let ctx2 = UserContext::default_new(&user2.username, &user2.user_id,
                                            &hex::encode(crypto::generate_nonce()),
                                            &hex::encode(crypto::generate_secret_key()),
                                            "pass2").unwrap();

        // WHEN creating the user THEN it should succeed
        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let (parent_crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx1,
            "input",
            &user1.user_id,
            "parent-keyable-id",
            "parent-keyable-type",
            "").unwrap();
        let mut conn = db_pool.get().unwrap();
        let size = crypto_repo.create(&parent_crypto_key, &mut conn).unwrap();
        assert_eq!(1, size);

        let (mut child_crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx1,
            "input",
            &user1.user_id,
            "keyable-id",
            "keyable-type",
            "").unwrap();
        child_crypto_key.parent_crypto_key_id = parent_crypto_key.crypto_key_id.clone();
        let mut conn = db_pool.get().unwrap();
        let size = crypto_repo.create(&child_crypto_key, &mut conn).unwrap();
        assert_eq!(1, size);

        let loaded = crypto_repo.get(&user1.user_id,
                                     "keyable-id",
                                     "keyable-type",
                                     &mut conn).unwrap();

        // User 2 should not be able to get crypto key
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());

        // Let's create ACL for access for parent
        {
            let ctx2 = ctx2.as_admin();
            let acl = ACLEntity::for_crypto_key(&ctx2.user_id, &parent_crypto_key.crypto_key_id);
            let size = acl_repo.create(&ctx2, &acl).await.unwrap();
            assert_eq!(1, size);
        }

        // User 2 should be able to get crypto key
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_ok());


        assert_eq!(child_crypto_key, loaded);
        let size = crypto_repo.delete(&user1.user_id,
                                      "keyable-id",
                                      "keyable-type",
                                      &mut conn).unwrap();
        assert_eq!(1, size);
        assert!(crypto_repo.get(&user1.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());
        assert!(crypto_repo.get(&user2.user_id,
                                "keyable-id",
                                "keyable-type",
                                &mut conn).is_err());
    }
}
