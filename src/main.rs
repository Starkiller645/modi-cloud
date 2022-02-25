use warp::Filter;

#[path = "./endpoints.rs"]
pub mod endpoints;
use endpoints::*;

pub mod console;
use console::{log, Endpoints};

extern crate pretty_env_logger;
extern crate log;

#[tokio::main]
async fn main() {

    pretty_env_logger::init();
    // GET /hello/:name => 200 OK with JSON body {hello: ":name"}
    
    log("Starting endpoint", Endpoints::Login);

    let hello_json = warp::path!("login" / String)
        .and(warp::get())
        .and(warp::header("Authorization"))
        .and_then(routes::auth_user);

    log("Starting endpoints", Endpoints::Upload);

    let upload_pkg = warp::path!("upload" / String)
        .and(warp::put())
        .and(warp::header("X-Modi-Username"))
        .and(warp::header("Authorization"))
        .and(warp::multipart::form().max_length(5_000_000_000))
        .and_then(routes::upload_pkg);

    log("Starting endpoint", Endpoints::Auth);
    let check_auth = warp::path!("auth" / String)
        .and(warp::get())
        .and(warp::header("Authorization"))
        .and_then(routes::try_auth);

    log("Starting endpoint", Endpoints::Package);
    let get_pkg = warp::path!("package" / String)
        .and(warp::get())
        .and_then(routes::get_pkg);

    let routes = hello_json
        .or(check_auth)
        .or(upload_pkg)
        .or(get_pkg);

    let log_routes = routes.with(warp::log("requests"));
    
    warp::serve(log_routes)
        .run(([127, 0, 0, 1], 3090))
        .await;
}
