use crate::crypto::compute_sha1_hex;
use crate::domain::error::PassError;
use crate::domain::models::PassResult;
use log::info;
use crate::locales::safe_localized_message;

/// email_compromised checks if an account with given email has been compromised  
pub(crate) async fn email_compromised(email: &str, api_key: &str) -> PassResult<String> {
    // Set the HIBP API endpoint and the user-agent header
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
        email
    );
    let client = reqwest::Client::builder()
        .user_agent(safe_localized_message("plexpass", None))
                        .build()?;

    let response = client
        .get(&url)
        .header("hibp-api-key", api_key)
        .send()
        .await;

    // Check the response
    match response {
        Ok(res) => {
            match res.text().await {
                Ok(text) => {
                    info!("-debug hibp---{}", text);
                    if text.contains("statusCode") || text.contains("hibp-api-key") {
                        return Err(PassError::runtime(
                            &safe_localized_message("email-compromise-error", Some(&["err", &text])),
                            None,
                        ));
                    }
                    Ok(text)
                }
                Err(err) => {
                    Err(PassError::from(err))
                }
            }
        }
        Err(err) => {
            Err(PassError::from(err))
        }
    }
}

/// password_compromised checks if an account with given password has been compromised  
pub(crate) async fn password_compromised(password: &str) -> PassResult<bool> {
    let hash_str = compute_sha1_hex(password).to_uppercase();

    // Split the hash
    let prefix = &hash_str[0..5];
    let suffix = &hash_str[5..];

    // Fetch the list of suffixes from HIBP
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let response = reqwest::get(&url).await?;
    let body = response.text().await?;

    // Check if our hash suffix is in the response
    Ok(body.lines().any(|line| line.starts_with(suffix)))
}

#[cfg(test)]
mod tests {
    use crate::hibp::{email_compromised, password_compromised};

    #[tokio::test]
    async fn test_should_check_for_password_compromised() {
        let ok = password_compromised("password").await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_should_check_for_email_compromised() {
        // "statusCode": 401, "message": "Access denied due to improperly formed hibp-api-key."
        assert!(email_compromised("test@gmail.com", "key").await.is_err());
    }
}
