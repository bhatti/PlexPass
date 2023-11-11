use crate::controller;
use crate::domain::error::PassError;
use crate::service::locator::ServiceLocator;
use actix_service::forward_ready;
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::{
    header::{HeaderName, HeaderValue},
    Method,
};
use actix_web::web::Data;
use actix_web::{Error, http};
use actix_web::HttpResponse;
use futures::future::{LocalBoxFuture, ok, Ready};

const API_PREFIX: &str = "/api";

const UI_SIGN_URL : &str = "/ui/signin";

// ignore routes
const IGNORE_ROUTES: [&str; 8] = [
    "/assets",
    "/metrics",
    "/ping",
    "/health",
    "/ui/signup",
    "/ui/signin",
    "/api/v1/auth/signup",
    "/api/v1/auth/signin",
];
const MESSAGE_INVALID_TOKEN: &str = "Invalid token, please login again";

pub struct Authentication;

impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthenticationMiddleware { service })
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let mut authenticate_pass: bool = false;

        // Bypass some account routes
        let mut headers = request.headers().clone();
        headers.append(
            HeaderName::from_static(http::header::CONTENT_TYPE.as_ref()),
            HeaderValue::from_static("true"),
        );

        if Method::OPTIONS == *request.method() {
            authenticate_pass = true;
        } else {
            for ignore_route in IGNORE_ROUTES.iter() {
                if request.path().starts_with(ignore_route) {
                    authenticate_pass = true;
                    break;
                }
            }
        }

        authenticate_pass = authenticate_pass || if request.path().starts_with(API_PREFIX) {
            Self::validate_api_token(&request) } else {Self::validate_ui_session(&request)};

        if authenticate_pass {
            let res = self.service.call(request);
            Box::pin(async move { res.await.map(ServiceResponse::map_into_left_body) })
        } else if request.path().starts_with(API_PREFIX) {
            let (request, _pl) = request.into_parts();
            let response = HttpResponse::Unauthorized()
                    .json(PassError::authentication(MESSAGE_INVALID_TOKEN))
                    .map_into_right_body();

            Box::pin(async { Ok(ServiceResponse::new(request, response)) })
        } else { // UI
            let (request, _pl) = request.into_parts();

            let response = HttpResponse::Found()
                .insert_header((http::header::LOCATION, UI_SIGN_URL))
                .finish()
                // constructed responses map to "right" body
                .map_into_right_body();

            return Box::pin(async { Ok(ServiceResponse::new(request, response)) });
        }
    }
}

impl<S, B> AuthenticationMiddleware<S> where B: 'static, S: Service<ServiceRequest, Response=ServiceResponse<B>, Error=Error>, S::Future: 'static {
    fn validate_api_token(req: &ServiceRequest) -> bool {
        if let Some(service_locator) = req.app_data::<Data<ServiceLocator>>() {
            if let Ok(res) =
            controller::verify_token_header(&req, service_locator)
            {
                return res;
            }
        }
        false
    }
    fn validate_ui_session(req: &ServiceRequest) -> bool {
        if let Some(service_locator) = req.app_data::<Data<ServiceLocator>>() {
            if let Ok(res) =
            controller::verify_session_cookie(&req, service_locator)
            {
                return res;
            }
        }
        false
    }
}
