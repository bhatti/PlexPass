use diesel::prelude::*;

use crate::dao::models::{UserEntity};
use crate::dao::schema::users::dsl::*;
use crate::dao::{DbConnection, DbPool, UserLookupRepository};
use crate::domain::error::PassError;
use crate::domain::models::{PassResult};

#[derive(Clone)]
pub(crate) struct UserLookupRepositoryImpl {
    pool: DbPool,
}

impl UserLookupRepositoryImpl {
    pub(crate) fn new(
        pool: DbPool,
    ) -> Self {
        UserLookupRepositoryImpl {
            pool,
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

impl UserLookupRepository for UserLookupRepositoryImpl {
    fn lookup_usernames(&self, q: &str) -> PassResult<Vec<String>> {
        let mut conn = self.connection()?;

        let match_username = format!("%{}%",q);
        let matched = users
            .filter(username.like(match_username))
            .limit(100)
            .load::<UserEntity>(&mut conn)?;
        Ok(matched.into_iter().map(|u|u.username).collect::<Vec<String>>())
    }

    fn lookup_userid_by_username(&self, match_username: &str) -> PassResult<String> {
        let mut conn = self.connection()?;
        let mut matched = users
            .filter(username.eq(match_username))
            .limit(1)
            .load::<UserEntity>(&mut conn)?;
        if matched.is_empty() {
            return Err(PassError::not_found(
                format!("user not found for username {}", match_username).as_str(),
            ));
        }
        Ok(matched.remove(0).user_id)
    }
}


#[cfg(test)]
mod tests {
}
