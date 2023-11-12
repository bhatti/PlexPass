// FIDO2 is an authentication standard that includes the WebAuthn and CTAP
// (Client-to-Authenticator Protocol) specifications.

use actix_session::Session;
use actix_web::web::{Data, Json, Path};
use actix_web::HttpResponse;
use log::{debug, info};
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::Webauthn;

use crate::auth::webauthn_startup::UserData;
use crate::domain::error::PassError;
use crate::domain::models::PassResult;

// The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// async fn start_registration(info: web::Json<RegistrationStartRequest>) -> HttpResponse {
//     let rp_id = "example.com";
//     let rp_origin = Url::parse("https://localhost:8080").expect("Invalid URL");
//     let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
//     let webauthn = builder.build().expect("Invalid configuration");
//
//     let user = SimpleUser {
//         username: info.username.clone(),
//         user_id: info.username.as_bytes().to_vec(),
//         credentials: vec![],
//     };
//
//     // Get the challenge for this user
//     let (challenge, _) = webauthn.generate_challenge(&user).unwrap();
//
//     // Normally, store the challenge in a secure session or a database
//     // For simplicity, we skip that here
//
//     HttpResponse::Ok().json(challenge)
// }

// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.
pub(crate) async fn start_register(
    username: Path<String>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
) -> PassResult<Json<CreationChallengeResponse>> {
    info!("Start register");

    // We get the username from the URL, but you could get this via form submission or
    // some other process. In some parts of Webauthn, you could also use this as a "display name"
    // instead of a username. Generally you should consider that the user *can* and *will* change
    // their username at any time.

    // Since a user's username could change at anytime, we need to bind to a unique id.
    // We use uuid's for this purpose, and you should generate these randomly. If the
    // username does exist and is found, we can match back to our unique id. This is
    // important in authentication, where presented credentials may *only* provide
    // the unique id, and not the username!

    let user_unique_id = {
        let users_guard = webauthn_users.lock().await;
        users_guard
            .name_to_id
            .get(username.as_str())
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };

    // Remove any previous registrations that may have occurred from the session.
    session.remove("reg_state");

    // If the user has any other credentials, we exclude these here so they can't be duplicate registered.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials = {
        let users_guard = webauthn_users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_unique_id, &username, &username, exclude_credentials)
        .map_err(|e| {
            debug!("challenge_register -> {:?}", e);
            PassError::authentication(&format!("unknown error {}", e))
        })?;

    // Note that due to the session store in use being a server side memory store, this is
    // safe to store the reg_state into the session since it is not client controlled and
    // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
    session
        .insert("reg_state", (username.as_str(), user_unique_id, reg_state))
        .expect("Failed to insert");

    info!("Registration Successful!");
    Ok(Json(ccr))
}

// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.
// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

pub(crate) async fn finish_register(
    req: Json<RegisterPublicKeyCredential>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
) -> PassResult<HttpResponse> {
    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) =
        session.get("reg_state")?.unwrap();

    session.remove("reg_state");

    let sk = webauthn
        .finish_passkey_registration(&req, &reg_state)
        .map_err(|e| {
            debug!("challenge_register -> {:?}", e);
            PassError::authentication(&format!("bad request {:?}", e))
        })?;

    let mut users_guard = webauthn_users.lock().await;

    //TODO: This is where we would store the credential in a db, or persist them in some other way.

    users_guard
        .keys
        .entry(user_unique_id)
        .and_modify(|keys| keys.push(sk.clone()))
        .or_insert_with(|| vec![sk.clone()]);

    users_guard.name_to_id.insert(username, user_unique_id);

    Ok(HttpResponse::Ok().finish())
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub(crate) async fn start_authentication(
    username: Path<String>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
) -> PassResult<Json<RequestChallengeResponse>> {
    info!("Start Authentication");
    // We get the username from the URL, but you could get this via form submission or
    // some other process.

    // Remove any previous authentication that may have occurred from the session.
    session.remove("auth_state");

    // Get the set of keys that the user possesses
    let users_guard = webauthn_users.lock().await;

    // Look up their unique id from the username
    let user_unique_id = users_guard
        .name_to_id
        .get(username.as_str())
        .copied()
        .ok_or(PassError::not_found("user not found"))?;

    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or(PassError::authentication("no credentials"))?;

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(allow_credentials)
        .map_err(|e| {
            debug!("challenge_authenticate -> {:?}", e);
            PassError::authentication(&format!("unknown error {:?}", e))
        })?;

    // Drop the mutex to allow the mut borrows below to proceed
    drop(users_guard);

    // Note that due to the session store in use being a server side memory store, this is
    // safe to store the auth_state into the session since it is not client controlled and
    // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
    session.insert("auth_state", (user_unique_id, auth_state))?;

    Ok(Json(rcr))
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

pub(crate) async fn finish_authentication(
    auth: Json<PublicKeyCredential>,
    session: Session,
    webauthn_users: Data<Mutex<UserData>>,
    webauthn: Data<Webauthn>,
) -> PassResult<HttpResponse> {
    let (user_unique_id, auth_state) = session
        .get("auth_state")?
        .ok_or(PassError::authentication("corrupt session"))?;

    session.remove("auth_state");

    let auth_result = webauthn
        .finish_passkey_authentication(&auth, &auth_state)
        .map_err(|_e| {
            PassError::authentication("bad request")
        })?;

    let mut users_guard = webauthn_users.lock().await;

    // Update the credential counter, if possible.
    users_guard
        .keys
        .get_mut(&user_unique_id)
        .map(|keys| {
            keys.iter_mut().for_each(|sk| {
                // This will update the credential if it's the matching
                // one. Otherwise it's ignored. That is why it is safe to
                // iterate this over the full list.
                sk.update_credential(&auth_result);
            })
        })
        .ok_or(PassError::authentication("no credentials"))?;

    info!("Authentication Successful!");
    Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_should_web_auth() {
        // .shutdown_timeout(60) // Graceful shutdown time for workers
        // .run();
        // thread::spawn(move || {
        //     thread::sleep(Duration::from_secs(30));
        //     info!("shutting down...");
        //     actix_rt::System::current().stop();
        // });
        //let _ = server.await;
        //assert!(false);
    }
}

//#[actix_web::main]
//async fn main() -> std::io::Result<()> {}
