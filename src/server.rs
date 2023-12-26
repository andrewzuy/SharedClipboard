use std::{fs};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder, HttpMessage};
use actix_web::body::{BoxBody, EitherBody};
use actix_web::error::ParseError::Header;
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use futures::StreamExt;
mod aes_encryption;

#[derive(Debug, Deserialize)]
struct Config{
    Host:String,
    Token:String,
    Passkey:String
}

struct Shared_State{
    Token: Mutex<String>,
    Text: Mutex<Vec<u8>>,
    Text_Hash: Mutex<String>,
    File: Mutex<Vec<u8>>,
    File_Name: Mutex<String>
}

#[get("/text_hash")]
async fn text_hash(_req: HttpRequest, shared_state: web::Data<Shared_State>) -> HttpResponse {
    let headers = _req.headers().clone();
    let mut expected_token = shared_state.Token.lock().unwrap().to_string().clone();
    if !headers.contains_key("TOKEN") {
        return reply_with_status_code(StatusCode::UNAUTHORIZED)
    } else{
        if headers.get("TOKEN").unwrap().eq(&expected_token.to_string().clone()){
            let responder = HttpResponse::Ok()
                .append_header(("HASH", shared_state.Text_Hash.lock().unwrap().clone().to_string()))
		.body("");
          return  responder
        }
        return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
    }
}

#[get("/text_get")]
async fn text_get(_req: HttpRequest, shared_state: web::Data<Shared_State>) -> HttpResponse {
    let headers = _req.headers().clone();
    let mut expected_token = shared_state.Token.lock().unwrap();
    let message = shared_state.Text.lock().unwrap().clone();
    if !headers.contains_key("TOKEN") {
        return reply_with_status_code(StatusCode::UNAUTHORIZED)
    } else{
        if headers.get("TOKEN").unwrap().eq(&expected_token.to_string().clone()){
                let responder = HttpResponse::Ok()
                    .content_type("application/binary")
                    .body(message);
                return responder
           
        }
        return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
    }
}

#[post("/text_post")]
async fn text_post(_req: HttpRequest, mut body: web::Payload ,shared_state: web::Data<Shared_State>) -> HttpResponse {
    let headers = _req.headers().clone();
    let expected_token = shared_state.Token.lock().unwrap();
    if !headers.contains_key("TOKEN") {
        return reply_with_status_code(StatusCode::UNAUTHORIZED)
    } else{
        if headers.get("TOKEN").unwrap().eq(&expected_token.to_string().clone()){
            if headers.contains_key("HASH"){
                let mut bytes = web::BytesMut::new();
                while let Some(item) = body.next().await {
                    let item = item.unwrap();
                    bytes.extend_from_slice(&item);
                }
                shared_state.Text.lock().unwrap().clear();
                shared_state.Text.lock().unwrap().extend_from_slice(&bytes);
                shared_state.Text_Hash.lock().unwrap().clear();
                shared_state.Text_Hash.lock().unwrap().push_str(headers.get("HASH").unwrap().to_str().unwrap());
                return  reply_with_status_code(StatusCode::OK)
            }
        }
        return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
    }
}

//------------------------
#[get("/file_get")]
async fn file_get(_req: HttpRequest, shared_state: web::Data<Shared_State>) -> HttpResponse {
    let headers = _req.headers().clone();
    let expected_token = shared_state.Token.lock().unwrap();
    let file = shared_state.File.lock().unwrap().clone();
    if !headers.contains_key("TOKEN") {
        return reply_with_status_code(StatusCode::UNAUTHORIZED)
    } else{
        if headers.get("TOKEN").unwrap().eq(&expected_token.to_string().clone()){
                let responder = HttpResponse::Ok()
                    .content_type("application/binary")
                    .append_header(("FILENAME", shared_state.File_Name.lock().unwrap().clone()))
                    .body(file);
                return responder
        }
        return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
    }
}

#[post("/file_post")]
async fn file_post(_req: HttpRequest, mut body: web::Payload ,shared_state: web::Data<Shared_State>) -> HttpResponse {
    let headers = _req.headers().clone();
    let expected_token = shared_state.Token.lock().unwrap();
    if !headers.contains_key("TOKEN") {
        return reply_with_status_code(StatusCode::UNAUTHORIZED)
    } else{
        if headers.get("TOKEN").unwrap().eq(&expected_token.to_string().clone()){
            let mut bytes = web::BytesMut::new();
            while let Some(item) = body.next().await {
                let item = item.unwrap();
                bytes.extend_from_slice(&item);
            }
	    match headers.get("FILENAME"){
	    Some(filename) => {
		shared_state.File_Name.lock().unwrap().clear();
		shared_state.File_Name.lock().unwrap().push_str(filename.to_str().unwrap());
		shared_state.File.lock().unwrap().clear();
		shared_state.File.lock().unwrap().extend_from_slice(&bytes);
		return  reply_with_status_code(StatusCode::OK)
	    },
	    None => return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
	    }
        }
        return reply_with_status_code(StatusCode::EXPECTATION_FAILED)
    }
}
//------------------------

fn reply_with_status_code(http_code:StatusCode) -> HttpResponse{
    HttpResponse::new(http_code)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = fs::read_to_string("config.json")
        .expect("Should have been able to read the file");
    let conf:Config =  serde_json::from_str(&config).unwrap();
    let token = conf.Token.clone();
    let host = conf.Host.clone();
    let socket_address:SocketAddr = host.parse().unwrap();
    let mut shared_state = web::Data::new(
        Shared_State {
            Token: Mutex::new(token.clone()),
            Text: Mutex::new(vec![]),
            File: Mutex::new(vec![]),
            Text_Hash: Mutex::new(String::new()),
            File_Name: Mutex::new(String::new()),
        });
    HttpServer::new(move || {
        App::new()
            .app_data(shared_state.clone())
            .service(text_hash)
            .service(text_get)
            .service(text_post)
            .service(file_post)
            .service(file_get)
    })
        .bind(socket_address)?
        .run()
        .await
}
