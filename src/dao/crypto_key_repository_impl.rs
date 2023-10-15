use diesel::prelude::*;

use crate::dao::models::CryptoKeyEntity;
use crate::dao::schema::crypto_keys;
use crate::dao::schema::crypto_keys::dsl::*;
use crate::dao::{CryptoKeyRepository, DbConnection};

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
        let mut items = crypto_keys
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(keyable_id.eq(match_keyable_id))
                    .and(keyable_type.eq(match_keyable_type)),
            )
            .limit(10)
            .load::<CryptoKeyEntity>(conn)?;
        if items.len() != 1 {
            log::warn!(
                "could not find crypto key for user {}, keyable {}/{}",
                match_user_id,
                match_keyable_type,
                match_keyable_id
            );
            return Err(diesel::result::Error::NotFound);
        }
        Ok(items.remove(0))
    }

    // delete an existing crypto_key.
    fn delete(
        &self,
        match_user_id: &str,
        match_keyable_id: &str,
        match_keyable_type: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        diesel::delete(
            crypto_keys.filter(
                user_id
                    .eq(match_user_id)
                    .and(keyable_id.eq(match_keyable_id))
                    .and(keyable_type.eq(match_keyable_type)),
            ),
        )
        .execute(conn)
    }
}
