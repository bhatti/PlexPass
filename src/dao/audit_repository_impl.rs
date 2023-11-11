use std::collections::HashMap;

use diesel::dsl::count;
use diesel::prelude::*;

use crate::dao::{AuditRepository, DbConnection, DbPool};
use crate::dao::models::{AuditEntity, UserContext};
use crate::dao::schema::audit_records;
use crate::dao::schema::audit_records::dsl::*;
use crate::domain::error::PassError;
use crate::domain::models::{AuditLog, PaginatedResult, PassResult};

#[derive(Clone)]
pub(crate) struct AuditRepositoryImpl {
    pool: DbPool,
}

impl AuditRepositoryImpl {
    pub(crate) fn new(pool: DbPool) -> Self {
        AuditRepositoryImpl {
            pool,
        }
    }
}

impl AuditRepository for AuditRepositoryImpl {
    fn create(
        &self,
        entity: &AuditEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        diesel::insert_into(audit_records::table)
            .values(entity)
            .execute(conn)
    }

    fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let mut conn = self.pool.get().map_err(|err| {
            PassError::database(format!("failed to get pool connection due to {}", err).as_str(), None, true)
        })?;
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let q = format!(
            "%{}%",
            predicates.get("context").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));

        match audit_records
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(q.as_str())
                             .or(message.like(q.as_str()))
                             .or(context.like(q.as_str())),
                    )
            )
            .select(count(audit_id))
            .first::<i64>(&mut conn)
        {
            Ok(count) => Ok(count),
            Err(err) => Err(PassError::from(err)),
        }
    }

    fn find(&self,
            ctx: &UserContext,
            predicates: HashMap<String, String>,
            offset: i64,
            limit: usize,
    ) -> PassResult<PaginatedResult<AuditLog>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let q = format!(
            "%{}%",
            predicates.get("context").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));

        let mut conn = self.pool.get().map_err(|err| {
            PassError::database(format!("failed to get pool connection due to {}", err).as_str(), None, true)
        })?;
        let entities = audit_records
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(q.as_str())
                             .or(message.like(q.as_str()))
                             .or(context.like(q.as_str())),
                    )
            )
            .offset(offset)
            .order(audit_records::created_at.desc())
            .limit(limit as i64)
            .load::<AuditEntity>(&mut conn)?;
        let logs = entities.into_iter().map(|l| l.to_log()).collect::<Vec<AuditLog>>();
        Ok(PaginatedResult::new(offset.clone(), limit.clone(), logs))
    }

    // delete_by_user_id delete all user audits
    fn delete_by_user_id(&self,
                         ctx: &UserContext,
                         other_user_id: &str,
                         c: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        if let Ok(()) = ctx.validate_user_id(other_user_id, || false) {
            diesel::delete(audit_records.filter(user_id.eq(other_user_id))).execute(c)
        } else {
            Ok(0)
        }
    }
}
