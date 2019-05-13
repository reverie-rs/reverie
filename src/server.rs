use std::fs;
use std::io;

use hyper::{Body, Method, Request, Response, StatusCode};
use hyper::service::service_fn;
use futures::{future, Future, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

pub static LOGICAL_TIME: AtomicUsize = AtomicUsize::new(744847200);

fn server_main(req: Request<Body>) -> BoxFut {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/schedule") => {
            Box::new(future::ok(Response::new(format!("{}", "ok")
                                .into())))
        }
        (&Method::GET, "/gettime") => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            Box::new(future::ok(Response::new(format!("{}", tick)
                                .into())))
        }
        _ => {
            Box::new(future::ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap()))
        }
    }
}

pub fn run() -> io::Result<()> {
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
