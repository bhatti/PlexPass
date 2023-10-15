use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;
use std::collections::HashMap;

use crate::dao::models::{CryptoKeyEntity, LookupEntity, UserContext};
use crate::dao::schema::lookups;
use crate::dao::schema::lookups::dsl::*;
use crate::dao::{DbConnection, DbPool, LookupRepository, Repository};
use crate::domain::error::PassError;
use crate::domain::models::{Lookup, PaginatedResult, PassResult};

#[derive(Clone)]
pub(crate) struct LookupRepositoryImpl {
    pool: DbPool,
}

impl LookupRepositoryImpl {
    pub(crate) fn new(pool: DbPool) -> Self {
        LookupRepositoryImpl { pool }
    }
    fn connection(&self) -> PassResult<DbConnection> {
        self.pool.get().map_err(|err| {
            PassError::database(
                format!("failed to get pool connection due to {}", err).as_str(),
                None,
                true,
            )
        })
    }
}

#[async_trait]
impl LookupRepository for LookupRepositoryImpl {}

#[async_trait]
impl Repository<Lookup, LookupEntity> for LookupRepositoryImpl {
    // create lookup.
    async fn create(&self, ctx: &UserContext, lookup: &Lookup) -> PassResult<usize> {
        // ensure user-context and lookup user-id matches
        ctx.validate_user_id(&lookup.user_id)?;
        let lookup_entity = LookupEntity::new(lookup);
        let mut conn = self.connection()?;
        match diesel::insert_into(lookups::table)
            .values(lookup_entity)
            .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    log::debug!("created lookup {:?} {}", lookup, size);
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to insert {}", lookup.lookup_id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // updates existing lookup.
    async fn update(&self, ctx: &UserContext, lookup: &Lookup) -> PassResult<usize> {
        ctx.validate_user_id(&lookup.user_id)?;

        let existing_lookup_entity = self.get_entity(ctx, &lookup.lookup_id).await?;

        let mut conn = self.connection()?;
        match diesel::update(
            lookups.filter(
                version
                    .eq(&existing_lookup_entity.version)
                    .and(lookup_id.eq(&lookup.lookup_id)),
            ),
        )
        .set((
            kind.eq(lookup.kind.to_string()),
            name.eq(&lookup.name),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    log::debug!("updated lookup {:?} {}", lookup, size);
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to update lookup {}", lookup.lookup_id,).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // get lookup by id
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<Lookup> {
        let lookup_entity = self.get_entity(ctx, id).await?;

        // ensure lookup belongs to user
        ctx.validate_user_id(&lookup_entity.user_id)?;

        Ok(lookup_entity.to_lookup())
    }

    // delete an existing lookup.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let lookup_entity = self.get_entity(ctx, id).await?;

        // ensure lookup belongs to user
        ctx.validate_user_id(&lookup_entity.user_id)?;

        let mut conn = self.connection()?;
        match diesel::delete(lookups.filter(lookup_id.eq(id))).execute(&mut conn) {
            Ok(size) => {
                if size > 0 {
                    log::debug!("deleted lookup lookup {}", id);
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to find records for deleting {}", id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    async fn get_crypto_key(&self, _ctx: &UserContext, _id: &str) -> PassResult<CryptoKeyEntity> {
        Err(PassError::validation("not implemented", None))
    }

    // get lookup entity by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<LookupEntity> {
        let mut conn = self.connection()?;
        let mut items = lookups
            .filter(lookup_id.eq(id))
            .limit(2)
            .load::<LookupEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many lookups for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("lookups not found for {}", id).as_str(),
            ));
        }
        let entity = items.remove(0);
        // ensure lookup belongs to user
        ctx.validate_user_id(&entity.user_id)?;
        Ok(entity)
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<Lookup> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find lookup [{}]", res.records.len()).as_str(),
            ));
        }

        Ok(res.records.remove(0))
    }

    // find lookups with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Lookup>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let match_kind = format!(
            "%{}%",
            predicates.get("kind").cloned().unwrap_or(String::from(""))
        );
        let match_name = format!(
            "%{}%",
            predicates.get("name").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));

        let mut conn = self.connection()?;
        let entities = lookups
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(match_kind.as_str()))
                    .and(name.like(match_name.as_str())),
            )
            .offset(offset)
            .order(lookups::kind)
            .then_order_by(lookups::name)
            .limit(limit as i64)
            .load::<LookupEntity>(&mut conn)?;

        let mut res = vec![];
        for entity in entities {
            let lookup = entity.to_lookup();
            res.push(lookup)
        }
        Ok(PaginatedResult::new(offset.clone(), limit.clone(), res))
    }

    async fn count(&self, _: &UserContext, predicates: HashMap<String, String>) -> PassResult<i64> {
        let mut conn = self.connection()?;
        let match_kind = format!(
            "%{}%",
            predicates.get("kind").cloned().unwrap_or(String::from(""))
        );
        let match_name = format!(
            "%{}%",
            predicates.get("name").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));
        match lookups
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(match_kind.as_str()))
                    .and(name.like(match_name.as_str())),
            )
            .count()
            .get_result::<i64>(&mut conn)
        {
            Ok(count) => Ok(count),
            Err(err) => Err(PassError::from(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::dao::factory::{create_lookup_repository, create_user_repository};
    use crate::dao::models::{LookupEntity, UserContext};
    use crate::domain::models::{Lookup, LookupKind, PassConfig, User};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_should_create_update_lookups() {
        let config = PassConfig::new();
        // GIVEN a user and lookup repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let lookup_repo = create_lookup_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a lookup
        let lookup = Lookup::new(&user.user_id, LookupKind::TAG, "name");
        let lookup_entity = LookupEntity::new(&lookup);
        // THEN it should succeed
        assert_eq!(1, lookup_repo.create(&ctx, &lookup).await.unwrap());

        // WHEN updating the lookup THEN it should succeed
        assert_eq!(1, lookup_repo.update(&ctx, &lookup).await.unwrap());

        // WHEN retrieving the lookup
        let loaded = lookup_repo
            .get(&ctx, &lookup_entity.lookup_id)
            .await
            .unwrap();
        // THEN it should have updated values.
        assert_eq!("name", loaded.name);
    }

    #[tokio::test]
    async fn test_should_create_delete_lookups() {
        let config = PassConfig::new();
        // GIVEN a user and lookup repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let lookup_repo = create_lookup_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a lookup
        let lookup = Lookup::new(&user.user_id, LookupKind::TAG, "name");
        // THEN it should succeed.
        assert_eq!(1, lookup_repo.create(&ctx, &lookup).await.unwrap());

        // WHEN deleting the lookup THEN it should succeed.
        assert_eq!(
            1,
            lookup_repo.delete(&ctx, &lookup.lookup_id).await.unwrap()
        );

        // WHEN retrieving the lookup THEN it should not find it.
        assert!(lookup_repo.get(&ctx, &lookup.lookup_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_lookups() {
        let config = PassConfig::new();
        // GIVEN a user and lookup repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let lookup_repo = create_lookup_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username1 = Uuid::new_v4().to_string();
        let username2 = Uuid::new_v4().to_string();
        let user1 = User::new(username1.as_str(), None, None);
        let ctx1 = UserContext::default_new(&username1, &user1.user_id, &salt, &pepper, "password")
            .unwrap();

        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());

        let user2 = User::new(username2.as_str(), None, None);
        let ctx2 = UserContext::default_new(&username2, &user2.user_id, &salt, &pepper, "password")
            .unwrap();
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let prefix1 = Uuid::new_v4().to_string();
        let prefix2 = Uuid::new_v4().to_string();
        let kinds = vec![LookupKind::TAG, LookupKind::CATEGORY];
        for i in 0..10 {
            let name1 = format!("{}_{}", prefix1, i);
            // WHEN creating a lookup
            let lookup1 = Lookup::new(&user1.user_id, kinds[i.clone() % 2].clone(), &name1);
            // THEN it should succeed.
            assert_eq!(1, lookup_repo.create(&ctx1, &lookup1).await.unwrap());

            // WHEN creating another lookup
            let name2 = format!("{}_{}", prefix2, i);
            let lookup2 = Lookup::new(&user2.user_id, kinds[i % 2].clone(), &name2);
            // THEN it should succeed.
            assert_eq!(1, lookup_repo.create(&ctx2, &lookup2).await.unwrap());
        }

        // WHEN finding by first user and TAG kind
        let res1 = lookup_repo
            .find(
                &ctx1,
                HashMap::from([
                    ("user_id".into(), user1.user_id.clone()),
                    ("kind".into(), LookupKind::TAG.to_string()),
                ]),
                0,
                500,
            )
            .await
            .unwrap();

        // THEN it should succeed and match half of the rows
        assert_eq!(5, res1.records.len());

        // WHEN counting by first user and TAG kind
        let count1 = lookup_repo
            .count(
                &ctx1,
                HashMap::from([
                    ("user_id".into(), user1.user_id.clone()),
                    ("kind".into(), LookupKind::TAG.to_string()),
                ]),
            )
            .await
            .unwrap();
        // THEN it should succeed and match half of the rows
        assert_eq!(5, count1);

        // WHEN finding by second user and CATEGORY kind
        let res2 = lookup_repo
            .find(
                &ctx2,
                HashMap::from([
                    ("user_id".into(), user2.user_id.clone()),
                    ("kind".into(), LookupKind::CATEGORY.to_string()),
                ]),
                0,
                500,
            )
            .await
            .unwrap();

        // THEN it should succeed and match half of the rows
        assert_eq!(5, res2.records.len());

        // WHEN counting by second user and CATEGORY kind
        let count2 = lookup_repo
            .count(
                &ctx2,
                HashMap::from([
                    ("user_id".into(), user2.user_id.clone()),
                    ("kind".into(), LookupKind::TAG.to_string()),
                ]),
            )
            .await
            .unwrap();
        // THEN it should succeed and match half of the rows
        assert_eq!(5, count2);
    }
}
