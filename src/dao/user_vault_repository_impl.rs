use diesel::prelude::*;
use std::collections::HashMap;

use crate::dao::models::UserVaultEntity;
use crate::dao::schema::users_vaults;
use crate::dao::schema::users_vaults::dsl::*;
use crate::dao::{DbConnection, UserVaultRepository};
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult};

#[derive(Clone)]
pub struct UserVaultRepositoryImpl {}

impl UserVaultRepositoryImpl {
    pub(crate) fn new() -> Self {
        UserVaultRepositoryImpl {}
    }
}

impl UserVaultRepository for UserVaultRepositoryImpl {
    // create user-vault
    fn create(
        &self,
        user_vault: &UserVaultEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        // add vault and crypto-key in the same transaction.
        conn.transaction(|c| {
            diesel::insert_into(users_vaults::table)
                .values(user_vault)
                .execute(c)
        })
    }

    // delete by vault-id user-vault
    fn delete_by_vault_id(
        &self,
        other_vault_id: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        let size =
            diesel::delete(users_vaults.filter(vault_id.eq(other_vault_id))).execute(conn)?;
        Ok(size)
    }

    // delete user-vault
    fn delete(
        &self,
        other_user_id: &str,
        other_vault_id: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        let size = diesel::delete(
            users_vaults.filter(
                vault_id
                    .eq(other_vault_id.to_string())
                    .and(user_id.eq(other_user_id.to_string())),
            ),
        )
        .execute(conn)?;
        Ok(size)
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    fn find_one(
        &self,
        predicates: HashMap<String, String>,
        conn: &mut DbConnection,
    ) -> PassResult<UserVaultEntity> {
        let mut res = self.find(predicates, 0, 5, conn)?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find user-vault [{}]", res.records.len()).as_str(),
            ));
        }
        Ok(res.records.remove(0))
    }

    // find all
    fn find(
        &self,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
        conn: &mut DbConnection,
    ) -> PassResult<PaginatedResult<UserVaultEntity>> {
        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let match_user_id = format!(
            "%{}%",
            predicates
                .get("user_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let items = users_vaults
            .filter(
                user_id
                    .like(match_user_id)
                    .and(vault_id.like(match_vault_id.as_str())),
            )
            .offset(offset)
            .limit(limit as i64)
            .load::<UserVaultEntity>(conn)?;

        Ok(PaginatedResult::new(offset.clone(), limit.clone(), items))
    }

    fn count(
        &self,
        predicates: HashMap<String, String>,
        conn: &mut DbConnection,
    ) -> PassResult<i64> {
        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let match_user_id = format!(
            "%{}%",
            predicates
                .get("user_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let count = users_vaults
            .filter(
                user_id
                    .like(match_user_id)
                    .and(vault_id.like(match_vault_id.as_str())),
            )
            .count()
            .get_result::<i64>(conn)?;
        Ok(count)
    }
}
