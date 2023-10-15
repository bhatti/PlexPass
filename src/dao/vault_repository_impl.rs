use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;

use crate::dao::models::{CryptoKeyEntity, UserContext, UserVaultEntity, VaultEntity};
use crate::dao::schema::users;
use crate::dao::schema::users_vaults;
use crate::dao::schema::vaults;
use crate::dao::schema::vaults::dsl::*;
use crate::dao::{CryptoKeyRepository, DbConnection, DbPool, Repository, UserRepository};
use crate::dao::{UserVaultRepository, VaultRepository};
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult, Vault};

#[derive(Clone)]
pub struct VaultRepositoryImpl {
    max_vaults_per_user: u32,
    pool: DbPool,
    user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
}

impl VaultRepositoryImpl {
    pub(crate) fn new(
        max_vaults_per_user: u32,
        pool: DbPool,
        user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
    ) -> Self {
        VaultRepositoryImpl {
            max_vaults_per_user,
            pool,
            user_vault_repository,
            user_repository,
            crypto_key_repository,
        }
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
impl VaultRepository for VaultRepositoryImpl {}

#[async_trait]
impl Repository<Vault, VaultEntity> for VaultRepositoryImpl {
    // create vault
    async fn create(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        ctx.validate_user_id(&vault.owner_user_id)?;
        // checking existing vaults for the user.
        let count = self
            .count(
                ctx,
                HashMap::from([("owner_user_id".into(), vault.owner_user_id.clone())]),
            )
            .await?;

        if count > self.max_vaults_per_user.clone() as i64 {
            return Err(PassError::validation(
                format!("too many vaults {} for the user.", count).as_str(),
                None,
            ));
        }
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &vault.owner_user_id)
            .await?;

        // create new vault-entity and crypto-keys
        let (vault_entity, vault_crypto_key) =
            VaultEntity::new_from_context_vault(ctx, &user_crypto_key, vault)?;

        let mut conn = self.connection()?;

        // add vault and crypto-key in the same transaction.
        let size = conn.transaction(|c| {
            let _ = diesel::insert_into(vaults::table)
                .values(&vault_entity)
                .execute(c)?;
            let _ = self.crypto_key_repository.create(&vault_crypto_key, c)?;
            self.user_vault_repository
                .create(&UserVaultEntity::new(&ctx.user_id, &vault.vault_id), c)
        })?;

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database("failed to insert vault", None, false))
        }
    }

    // updates existing vault item
    async fn update(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &vault.owner_user_id)
            .await?;
        let mut vault_entity = self.get_entity(ctx, &vault.vault_id).await?;
        let vault_crypto_key = self.get_crypto_key(ctx, &vault.vault_id).await?;

        // Only vault owner can update vault
        let _ = ctx.validate_user_id(&vault_entity.owner_user_id)?;

        // match version for optimistic concurrency control
        vault_entity.match_version(vault.version.clone())?;

        // updating vault
        let _ = vault_entity.update_from_context_vault(
            ctx,
            &user_crypto_key,
            vault,
            &vault_crypto_key,
        )?;

        // updating vault in database
        let mut conn = self.connection()?;
        let size = diesel::update(
            vaults.filter(
                vault_id
                    .eq(&vault_entity.vault_id)
                    .and(version.eq(&vault.version)),
            ),
        )
        .set((
            version.eq(vault_entity.version.clone() + 1),
            title.eq(&vault_entity.title),
            nonce.eq(&vault_entity.nonce),
            encrypted_value.eq(&vault_entity.encrypted_value),
            updated_at.eq(&vault_entity.updated_at),
        ))
        .execute(&mut conn)?;

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to find vault {}", vault_entity.vault_id).as_str(),
                None,
                false,
            ))
        }
    }

    // find by key
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<Vault> {
        let vault_entity = self.get_entity(ctx, id).await?;
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &vault_entity.owner_user_id)
            .await?;
        let vault_crypto_key = self.get_crypto_key(ctx, id).await?;

        vault_entity.to_vault(ctx, &user_crypto_key, &vault_crypto_key)
    }

    // delete vault
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        // finding vault
        let vault = self
            .find_one(ctx, HashMap::from([("vault_id".into(), id.into())]))
            .await?;

        let mut conn = self.connection()?;
        // If owner then delete vault and all associations otherwise just remove the association.
        let size = if vault.owner_user_id == ctx.user_id {
            conn.transaction(|c| {
                let _ = self.user_vault_repository.delete_by_vault_id(id, c)?;
                diesel::delete(vaults.filter(vault_id.eq(id.to_string()))).execute(c)
            })?
        } else {
            self.user_vault_repository
                .delete(&ctx.user_id, id, &mut conn)?
        };

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to find vault {}", id).as_str(),
                None,
                false,
            ))
        }
    }

    // find crypto key by id
    async fn get_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity> {
        let mut conn = self.connection()?;
        let crypto_key = self
            .crypto_key_repository
            .get(&ctx.user_id, id, "Vault", &mut conn)?;
        ctx.validate_user_id(&crypto_key.user_id)?;
        Ok(crypto_key)
    }

    // find vault_entity and crypto key by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<VaultEntity> {
        let mut conn = self.connection()?;

        let mut items = users::table
            .inner_join(users_vaults::table.inner_join(vaults::table))
            .filter(
                users_vaults::user_id
                    .eq(&ctx.user_id)
                    .and(users_vaults::vault_id.eq(id)),
            )
            .select(VaultEntity::as_select())
            .limit(2)
            .load::<VaultEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many vaults for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("vault not found for key {}", id).as_str(),
            ));
        }
        let vault_entity = items.remove(0);
        Ok(vault_entity)
    }
    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<Vault> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find vault [{}]", res.records.len()).as_str(),
            ));
        }
        Ok(res.records.remove(0))
    }

    // find all
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        page_size: usize,
    ) -> PassResult<PaginatedResult<Vault>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("username".into(), ctx.username.clone());
        }

        let mut conn = self.connection()?;
        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let match_owner_user_id = format!(
            "%{}%",
            predicates
                .get("owner_user_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let entities = users::table
            .inner_join(users_vaults::table.inner_join(vaults::table))
            .filter(
                users_vaults::user_id.eq(&ctx.user_id).and(
                    owner_user_id
                        .like(match_owner_user_id)
                        .and(users_vaults::vault_id.like(match_vault_id)),
                ),
            )
            .select(VaultEntity::as_select())
            .offset(offset)
            .limit(page_size.clone() as i64)
            .order(vaults::title)
            .load::<VaultEntity>(&mut conn)?;

        let mut res = vec![];
        for entity in entities {
            let mut vault = Vault::new(&entity.owner_user_id, &entity.title);
            vault.vault_id = entity.vault_id.clone();
            vault.version = entity.version;
            vault.created_at = Some(entity.created_at);
            vault.updated_at = Some(entity.updated_at);
            res.push(vault);
        }

        Ok(PaginatedResult::new(offset.clone(), page_size.clone(), res))
    }

    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("username".into(), ctx.username.clone());
        }

        let mut conn = self.connection()?;
        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let match_owner_user_id = format!(
            "%{}%",
            predicates
                .get("owner_user_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let count = users::table
            .inner_join(users_vaults::table.inner_join(vaults::table))
            .filter(
                users_vaults::user_id.eq(&ctx.user_id).and(
                    owner_user_id
                        .like(match_owner_user_id)
                        .and(users_vaults::vault_id.like(match_vault_id)),
                ),
            )
            .count()
            .get_result::<i64>(&mut conn)?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use crate::crypto;
    use crate::dao::factory::{create_user_repository, create_vault_repository};
    use crate::dao::models::UserContext;
    use crate::domain::models::{PassConfig, User, Vault};

    #[tokio::test]
    async fn test_should_create_update_vault() {
        let config = PassConfig::new();
        // GIVEN a user and vault repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a vault
        let mut vault = Vault::new(&user.user_id, "title");
        // THEN it should succeed
        assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());

        // WHEN updating the vault
        vault.title = "new-value".into();
        // THEN it should succeed
        assert_eq!(1, vault_repo.update(&ctx, &vault).await.unwrap());

        // WHEN retrieving the vault
        let loaded = vault_repo.get(&ctx, &vault.vault_id).await.unwrap();

        // THEN it should have updated values
        assert_eq!("new-value", loaded.title);
    }

    #[tokio::test]
    async fn test_should_create_delete_vault() {
        let config = PassConfig::new();
        // GIVEN a user and vault repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a vault
        let vault = Vault::new(user.user_id.as_str(), "title");
        // THEN it should succeed
        assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());

        // WHEN deleting the vault THEN it should succeed
        assert_eq!(1, vault_repo.delete(&ctx, &vault.vault_id).await.unwrap());

        // WHEN retrieving the vault after deleting, THEN it should fail
        assert!(vault_repo.get(&ctx, &vault.vault_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_vaults() {
        let config = PassConfig::new();
        // GIVEN a user and vault repositories
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let user_repo = create_user_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        for i in 0..3 {
            // WHEN creating a vault
            let vault = Vault::new(user.user_id.as_str(), format!("tile{}", i).as_str());
            // THEN it should succeed
            assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());
        }

        // WHEN finding vaults by user_id
        let res = vault_repo
            .find(
                &ctx,
                HashMap::from([("user_id".into(), user.user_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        // THEN it should find all vaults for the user
        assert_eq!(3, res.records.len());

        // WHEN counting vaults by user_id
        let count = vault_repo
            .count(
                &ctx,
                HashMap::from([("user_id".into(), user.user_id.clone())]),
            )
            .await
            .unwrap();
        // THEN it should match
        assert_eq!(3, count);

        let vault_id = res.records.first().unwrap().vault_id.clone();
        // WHEN finding vaults by user_id and vault_id
        let res = vault_repo
            .find(
                &ctx,
                HashMap::from([
                    ("user_id".into(), user.user_id.clone()),
                    ("vault_id".into(), vault_id.clone()),
                ]),
                0,
                500,
            )
            .await
            .unwrap();
        // THEN it should find one vault for the user
        assert_eq!(1, res.records.len());

        // WHEN counting vaults by user_id and vault-id
        let count = vault_repo
            .count(
                &ctx,
                HashMap::from([
                    ("user_id".into(), user.user_id.clone()),
                    ("vault_id".into(), vault_id.clone()),
                ]),
            )
            .await
            .unwrap();
        // THEN it should match one
        assert_eq!(1, count);
    }
}
