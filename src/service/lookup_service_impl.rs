use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::LookupRepository;
use crate::domain::models::{all_categories, Lookup, LookupKind, PassConfig, PassResult};
use crate::service::LookupService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct LookupServiceImpl {
    config: PassConfig,
    lookup_repository: Arc<dyn LookupRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl LookupServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        lookup_repository: Arc<dyn LookupRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            lookup_repository,
            metrics: PassMetrics::new("lookup_service", registry)?,
        })
    }

    async fn get_lookups_by_kind(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
    ) -> PassResult<Vec<Lookup>> {
        let items = self
            .lookup_repository
            .find(
                ctx,
                HashMap::from([("kind".into(), kind.to_string())]),
                0,
                self.config.max_lookup_entries as usize,
            )
            .await?;
        let mut res = vec![];
        for item in items.records {
            res.push(item);
        }
        Ok(res)
    }

    async fn get_lookup_by_name(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
        name: &str,
    ) -> PassResult<Lookup> {
        self.lookup_repository
            .find_one(
                ctx,
                HashMap::from([
                    ("kind".into(), kind.to_string()),
                    ("name".into(), name.into()),
                ]),
            )
            .await
    }
}

#[async_trait]
impl LookupService for LookupServiceImpl {
    async fn create_lookup(&self, ctx: &UserContext, lookup: &Lookup) -> PassResult<usize> {
        let _ = self.metrics.new_metric("create_lookup");
        self.lookup_repository.create(ctx, lookup).await
    }

    async fn delete_lookup(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
        name: &str,
    ) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_lookup");
        let lookup_entity = self.get_lookup_by_name(ctx, kind, name).await?;
        self.lookup_repository
            .delete(ctx, &lookup_entity.lookup_id)
            .await
    }

    async fn get_lookups(&self, ctx: &UserContext, kind: LookupKind) -> PassResult<Vec<Lookup>> {
        let _ = self.metrics.new_metric("get_lookups");
        self.get_lookups_by_kind(ctx, kind).await
    }

    // get default and user categories combined
    async fn get_categories(&self, ctx: &UserContext) -> PassResult<Vec<String>> {
        let user_categories = self.get_lookups_by_kind(ctx, LookupKind::CATEGORY).await?;
        let mut categories = HashSet::new();
        for cat in user_categories {
            categories.insert(cat.name);
        }
        for cat in all_categories() {
            categories.insert(cat);
        }
        let mut categories: Vec<_> = categories.into_iter().collect();
        categories.sort();
        Ok(categories)
    }

    async fn get_lookup(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
        name: &str,
    ) -> PassResult<Lookup> {
        let _ = self.metrics.new_metric("get_lookup");
        self.get_lookup_by_name(ctx, kind, name).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{all_categories, Lookup, LookupKind, PassConfig, User};
    use crate::service::factory::{create_lookup_service, create_user_service};

    #[tokio::test]
    async fn test_should_create_lookup() {
        let config = PassConfig::new();
        // GIVEN user-service and lookup-service
        let user_service = create_user_service(&config).await.unwrap();
        let lookup_service = create_lookup_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "Bakcru5h&r]fIt@", HashMap::new()).await.unwrap();

        // WHEN creating a lookup
        let lookup = Lookup::new(&user.user_id, LookupKind::TAG, "name");

        // THEN it should succeed
        assert_eq!(
            1,
            lookup_service.create_lookup(&ctx, &lookup).await.unwrap()
        );

        // WHEN retrieving the lookup
        let loaded = lookup_service
            .get_lookup(&ctx, LookupKind::TAG, "name")
            .await
            .unwrap();
        // THEN lookup should have matched attributes.
        assert_eq!("name", loaded.name);
    }

    #[tokio::test]
    async fn test_should_create_delete_lookups() {
        let config = PassConfig::new();
        // GIVEN user-service and lookup-service
        let user_service = create_user_service(&config).await.unwrap();
        let lookup_service = create_lookup_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN creating an lookup
        let lookup = Lookup::new(&user.user_id, LookupKind::CATEGORY, "name1");

        // THEN it should succeed
        assert_eq!(
            1,
            lookup_service.create_lookup(&ctx, &lookup).await.unwrap()
        );

        // WHEN deleting the lookup
        let deleted = lookup_service
            .delete_lookup(&ctx, lookup.kind, &lookup.name)
            .await
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the lookup after deleting it THEN it should not find it.
        let res = lookup_service
            .get_lookup(&ctx, LookupKind::CATEGORY, "name1")
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_lookups() {
        let config = PassConfig::new();
        // GIVEN user-service and lookup-service
        let user_service = create_user_service(&config).await.unwrap();
        let lookup_service = create_lookup_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "Bakcru5h&r]fIt@", HashMap::new()).await.unwrap();

        let kinds = [LookupKind::CATEGORY, LookupKind::TAG];
        for i in 0..10 {
            // WHEN creating an lookup
            let lookup = Lookup::new(
                &user.user_id,
                kinds[i % 2].clone(),
                format!("name_{}", i).as_str(),
            );
            assert_eq!(
                1,
                lookup_service.create_lookup(&ctx, &lookup).await.unwrap()
            );
        }

        let res1 = lookup_service
            .get_lookups(&ctx, LookupKind::CATEGORY)
            .await
            .unwrap();
        assert_eq!(5, res1.len());
        let res2 = lookup_service
            .get_lookups(&ctx, LookupKind::TAG)
            .await
            .unwrap();
        assert_eq!(5, res2.len());

        let res3 = lookup_service.get_categories(&ctx).await.unwrap();
        assert_eq!(5 + all_categories().len(), res3.len());
    }
}
