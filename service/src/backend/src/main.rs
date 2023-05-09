use actix_web::{get, middleware::Logger, App, HttpResponse, HttpServer, Responder};

#[get("/user/alo")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hallo")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(hello)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
