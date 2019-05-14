use std::fs;
use std::io;

use hyper::{Body, Method, Request, Response, StatusCode, header};
use hyper::service::service_fn;
use futures::{future, Future, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type BoxFut = Box<Future<Item = Response<Body>, Error = GenericError> + Send>;

pub static LOGICAL_TIME: AtomicUsize = AtomicUsize::new(744847200);

fn server_main(req: Request<Body>) -> BoxFut {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/schedule") => {
            Box::new(future::ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("ok"))
                                .unwrap()))
        }
        (&Method::GET, "/gettime") => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            Box::new({
                let json = json!({
                    "seconds": tick,
                    "nanoseconds": 0,
                });
                let rsp = Response::builder()
                    .header(header::CONTENT_TYPE,
                            "application/json")
                    .status(StatusCode::OK)
                    .body(Body::from(json.to_string()))
                    .unwrap();
                future::ok(rsp)
            })
        }
        _ => {
            Box::new(future::ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap()))
        }
    }
}

pub fn run_local() -> io::Result<()> {
    let path = "/tmp/detsched.sock";
    if let Err(err) = fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err);
        }
    }

    let svr = hyperlocal::server::Server::bind(path, || service_fn(server_main))?;
    log::info!("Listening on unix://{}", path);
    svr.run()?;
    Ok(())
}

pub fn run() -> io::Result<()> {
    let path = "0.0.0.0:8000".parse().unwrap();

    let new_service = move || {
        service_fn(|req|server_main(req))
    };
    let svr = hyper::Server::bind(&path)
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));
    log::info!("Listening on {}", path);
    hyper::rt::run(svr);
    Ok(())
}
