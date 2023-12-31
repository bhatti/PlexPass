use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;

use crate::dao::models::{ACLEntity, AuditEntity, AuditKind, CryptoKeyEntity, UserContext, UserVaultEntity, VaultEntity, WRITE_PERMISSION};
use crate::dao::schema::users;
use crate::dao::schema::users_vaults;
use crate::dao::schema::vaults;
use crate::dao::schema::vaults::dsl::*;
use crate::dao::{AuditRepository, CryptoKeyRepository, DbConnection, DbPool, Repository, UserRepository};
use crate::dao::{UserVaultRepository, VaultRepository};
use crate::dao::acl_repository_impl::ACLRepositoryImpl;
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult, ShareVaultPayload, Vault, VaultKind};

#[derive(Clone)]
pub struct VaultRepositoryImpl {
    max_vaults_per_user: u32,
    pool: DbPool,
    user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
    audit_repository: Arc<dyn AuditRepository + Send + Sync>,
}

impl VaultRepositoryImpl {
    pub(crate) fn new(
        max_vaults_per_user: u32,
        pool: DbPool,
        user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
        audit_repository: Arc<dyn AuditRepository + Send + Sync>,
    ) -> Self {
        VaultRepositoryImpl {
            max_vaults_per_user,
            pool,
            user_vault_repository,
            user_repository,
            crypto_key_repository,
            audit_repository,
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

    // This method is called by the owner of vault so ctx belongs to the owner not target user.
    pub fn shared_delete(
        ctx: &UserContext,
        payload: &ShareVaultPayload,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
        audit_repository: Arc<dyn AuditRepository + Send + Sync>,
        conn: &mut DbConnection,
    ) -> PassResult<usize> {
        let vault_crypto_key = crypto_key_repository.get(&payload.target_user_id, &payload.vault_id, "Vault", conn);

        // remove crypto-keys in the same transaction.
        // Note: We will remove UserVaultEntity relationship and associated acl in share_vault_account_repository's unshare_vault method.
        let size = conn.transaction(|c| {
            let _ = crypto_key_repository.delete(&payload.target_user_id, &payload.vault_id, "Vault", c)?;
            match vault_crypto_key {
                Ok(vault_crypto_key) => {
                    let _ = ACLRepositoryImpl::delete_acl(&payload.target_user_id, &vault_crypto_key.crypto_key_id, "CryptoKeyEntity", c)?;
                    if !vault_crypto_key.parent_crypto_key_id.is_empty() {
                        let _ = ACLRepositoryImpl::delete_acl(&payload.target_user_id, &vault_crypto_key.parent_crypto_key_id, "CryptoKeyEntity", c)?;
                    }
                }
                Err(_) => {
                   log::info!("could not find vault crypto key for user {} vault {}", &payload.target_user_id, &payload.vault_id);
                }
            }
            audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::UnsharedCreatedVault, &payload.vault_id, "vault unshared"),
                                    c)
        })?;

        if size > 0 {
            log::info!("deleted link to shared vault {}", &payload.vault_id);
            Ok(size)
        } else {
            Err(PassError::database("failed to delete shared-link to vault", None, false))
        }
    }

    // This method is called by the recipient user when they log in so ctx belongs to the target user.
    pub async fn accept_shared_create(
        ctx: &UserContext,
        payload: &ShareVaultPayload,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
        audit_repository: Arc<dyn AuditRepository + Send + Sync>,
        conn: &mut DbConnection,
    ) -> PassResult<usize> {
        // Add access to the shared data from Inbox message
        let user_crypto_key = user_repository.get_crypto_key(ctx, &ctx.user_id).await?;
        let user_private_key = user_crypto_key.decrypted_private_key_with_symmetric_input(ctx, &ctx.secret_key)?;

        let vault_crypto_key = CryptoKeyEntity::clone_from_sharing(
            ctx,
            &user_private_key,
            &user_crypto_key.public_key,
            &payload.encrypted_crypto_key,
        )?;

        // we have separated creating association and acl for vault to share-vault so that we can
        // easily disable them if target user never signs in.
        // add crypto-key in the same transaction.
        let size = conn.transaction(|c| {
            let _ = crypto_key_repository.create(&vault_crypto_key, c)?;
            // we will create UserVaultEntity and acl for vault in share_vault_account_repository's share_vault method.

            // Add ACL rules so that target user can access vault and its crypto keys along with
            // Accounts
            let acl_crypto_key = ACLEntity::for_crypto_key(&ctx.user_id,
                                                           &vault_crypto_key.crypto_key_id);
            let _ = ACLRepositoryImpl::create_conn(&acl_crypto_key, c)?;
            if !vault_crypto_key.parent_crypto_key_id.is_empty() {
                let acl_crypto_key = ACLEntity::for_crypto_key(&ctx.user_id,
                                                               &vault_crypto_key.parent_crypto_key_id);
                let _ = ACLRepositoryImpl::create_conn(&acl_crypto_key, c)?;
            }
            audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::AcceptedSharedVault, &payload.vault_id, "vault shared accepted"),
                                    c)
        })?;

        if size > 0 {
            log::info!("created shared vault {}", &payload.vault_id);
            Ok(size)
        } else {
            Err(PassError::database("failed to accept shared vault", None, false))
        }
    }
}

#[async_trait]
impl VaultRepository for VaultRepositoryImpl {}

#[async_trait]
impl Repository<Vault, VaultEntity> for VaultRepositoryImpl {
    // create vault
    async fn create(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        ctx.validate_user_id(&vault.owner_user_id, || false)?; // no acl check
        // checking existing vaults for the user.
        let count = self
            .count(
                ctx,
                HashMap::from([("owner_user_id".into(), vault.owner_user_id.clone())]),
            )
            .await?;

        if count > self.max_vaults_per_user as i64 {
            return Err(PassError::validation(
                format!("too many vaults {} for the user.", count).as_str(),
                None,
            ));
        }

        // Finding user crypto key based on vault owner
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
            let _ = self.user_vault_repository
                .create(&UserVaultEntity::new(&ctx.user_id, &vault.vault_id, &HashMap::new()), c)?;
            self.audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::CreatedVault, &vault.vault_id, "vault created"),
                                         c)
        })?;

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database("failed to insert vault", None, false))
        }
    }

    // updates existing vault item
    async fn update(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        // Retrieve user-crypto key based on owner as only owner can edit it.
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id) // we don't need to use owner_user_id
            .await?;
        let mut vault_entity = self.get_entity(ctx, &vault.vault_id).await?;
        let vault_crypto_key = self.get_crypto_key(ctx, &vault.vault_id).await?;

        // Only vault owner or ACL allowed users can update vault
        let _ = ctx.validate_user_id(&vault_entity.owner_user_id,
                                     || {
                                         if let Ok(mut conn) = self.connection() {
                                             ACLRepositoryImpl::check_acl(
                                                 &ctx.user_id,
                                                 &vault.vault_id,
                                                 "Vault",
                                                 WRITE_PERMISSION,
                                                 &mut conn)
                                         } else {
                                             false
                                         }
                                     })?;
        // match version for optimistic concurrency control
        vault_entity.match_version(vault.version)?;

        // updating vault
        let _ = vault_entity.update_from_context_vault(
            ctx,
            &user_crypto_key,
            vault,
            &vault_crypto_key,
        )?;

        let mut conn = self.connection()?;
        // updating vault in database
        let size = diesel::update(
            vaults.filter(
                vault_id
                    .eq(&vault_entity.vault_id)
                    .and(version.eq(&vault.version)),
            ),
        )
            .set((
                version.eq(vault_entity.version + 1),
                title.eq(&vault_entity.title),
                kind.eq(&vault_entity.kind),
                icon.eq(&vault_entity.icon),
                nonce.eq(&vault_entity.nonce),
                encrypted_value.eq(&vault_entity.encrypted_value),
                updated_at.eq(&vault_entity.updated_at),
            ))
            .execute(&mut conn)?;

        if size > 0 {
            let _ = self.audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::UpdatedVault, &vault.vault_id, "vault updated"),
                                                 &mut conn)?;
            log::info!("updated vault {}", &vault.vault_id);
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
            .get_crypto_key(ctx, &ctx.user_id)
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
                let _ = self.crypto_key_repository.delete(&ctx.user_id, id, "Vault", c)?;
                diesel::delete(vaults.filter(vault_id.eq(id.to_string()))).execute(c)
            })?
        } else {
            self.user_vault_repository
                .delete(&ctx.user_id, id, &mut conn)?
        };

        if size > 0 {
            let _ = self.audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::DeletedVault, &vault.vault_id, "vault deleted"),
                                                 &mut conn)?;
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
        ctx.validate_user_id(&crypto_key.user_id, || false)?; // no acl check
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

        let mut vault_entity: VaultEntity = items.remove(0);
        if vault_entity.owner_user_id != ctx.user_id &&
            !vault_entity.title.to_lowercase().contains("shared") {
            vault_entity.title = format!("{} [Shared]", vault_entity.title);
        }
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
            .limit(page_size as i64)
            .order(vaults::created_at) //vaults::title
            .load::<VaultEntity>(&mut conn)?;

        let mut res = vec![];
        for entity in entities {
            let mut vault = Vault::new(&entity.owner_user_id, &entity.title, VaultKind::from(entity.kind.as_str()));
            vault.vault_id = entity.vault_id.clone();
            vault.version = entity.version;
            vault.icon = entity.icon;
            vault.created_at = Some(entity.created_at);
            vault.updated_at = Some(entity.updated_at);
            if entity.owner_user_id != ctx.user_id &&
                !entity.title.to_lowercase().contains("shared") {
                vault.title = format!("{} [Shared]", entity.title);
            }
            res.push(vault);
        }

        Ok(PaginatedResult::new(offset, page_size, res))
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
    use crate::domain::models::{PassConfig, User, Vault, VaultKind};

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
        let mut vault = Vault::new(&user.user_id, "title", VaultKind::Logins);
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
        let vault = Vault::new(user.user_id.as_str(), "title", VaultKind::Logins);
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
            let vault = Vault::new(user.user_id.as_str(), format!("tile{}", i).as_str(), VaultKind::Logins);
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
