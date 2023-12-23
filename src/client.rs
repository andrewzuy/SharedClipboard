use std::io::{stdin};
use std::sync::{Arc, Mutex};
extern crate clipboard;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use std::{fs, thread,time};
use serde::{Deserialize};
use reqwest::blocking::Client;
mod aes_encryption;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use crate::aes_encryption::aes_encryption::{AesEngine, Message, FileMessage};

#[derive(Debug,Deserialize, Clone)]
struct Config{
    Host:String,
    Token:String,
    Passkey:String
}

fn tui_scan(config:Arc<Mutex<Config>>, client:Arc<Client>){
    let mut temp = String::new();
    let key = aes_encryption::aes_encryption::get_key(config.clone().lock().unwrap().clone().Passkey);
    loop {
        print!("{}[2J", 27 as char);
        println!("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
        println!("┃Enter F to send a file, R to receive...┃");
        println!("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
        let _ = stdin().read_line(&mut temp);
        if temp.contains("F") {
            print!("{}[2J", 27 as char);          
            println!("┏━━━━━━━━━━━━━━━━━━━━━━━━━┓");
            println!("┃Copy the filepath here...┃");
            println!("┗━━━━━━━━━━━━━━━━━━━━━━━━━┛");
            temp.clear();
            _ = stdin().read_line(&mut temp);
	    let file_str = clear_up_path(temp.clone());
	    let file_path = Path::new(&file_str);
	    println!("File path: {:?}, does exists: {:?}", file_path.file_name(), file_path.exists());
	    let file_open = std::fs::read(file_path);
	    match file_open{
		Ok(file) => {
		    let file_message = FileMessage::new(file_path.file_name().unwrap().to_str().unwrap().to_string(), file);
		    post_file(config.clone(), file_message.file.encrypt_aes_256_cbc(&key), file_message.filename.clone(), client.clone())
		},
		Err(err) => eprintln!("Failed to post the file because of: {}", err)
	    }
	    println!("Hit enter...");
	    _ = stdin().read_line(&mut temp);
        }
	if temp.contains("R") {
            print!("{}[2J", 27 as char);
	    println!("Getting file...");
            let encrypted_message = get_file(config.clone(),client.clone());
	    if encrypted_message.filename.len() > 0 {
                println!("Received {}", encrypted_message.clone().filename);
		let encrypted_file = encrypted_message.clone().file.value;
		let file_decrypted = encrypted_message.file.decrypt_aes_256_cbc(encrypted_file, &key).value;
		let _ = fs::create_dir("shared");
		let mut path = Path::new("shared/");
		let mut file = File::create(path.join(encrypted_message.filename)).unwrap();
		file.write_all(&file_decrypted);
		println!("Create file {}", path.display());
	    }
	    println!("Hit enter...");
	    _ = stdin().read_line(&mut temp);
        }
    }
}

fn clear_up_path(raw: String) -> String{
    let mut result = String::new();
    result.push_str(raw.trim().replace("/n","").replace("'","").trim());
    result
}

fn watch_clipboard(config:Arc<Mutex<Config>>, client:Arc<Client>){
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let key = aes_encryption::aes_encryption::get_key(config.clone().lock().unwrap().clone().Passkey);
    let mut prev_local_clipboard_hash = String::new();
    let mut prev_remote_clipboard_hash = String::new();
    let mut temp_vec:Vec<u8> = Vec::new();
    loop {
        thread::sleep(time::Duration::from_secs(1));
        let tmp = ctx.get_contents();
	match tmp{
	    Ok(tmp) => {
		let mut flag = true;
		let local_clip_message = Message::new(tmp.as_bytes().to_vec());
		let new_remote_hash = get_text_hash(config.clone(), client.clone());
		if new_remote_hash != prev_remote_clipboard_hash{
		    let encrypted_text = get_text(config.clone(), client.clone());
		    let decrypted_text = local_clip_message.decrypt_aes_256_cbc(encrypted_text.clone(), &key);
		    temp_vec = encrypted_text.clone();
		    match String::from_utf8(decrypted_text.value){
			Ok(str) =>  ctx.set_contents(str).unwrap(),
			Err(err) => eprintln!("failed to parse decrypted text, {}", err) 
		    }
		    prev_remote_clipboard_hash = new_remote_hash;
		    flag = false;
		}
		if flag && prev_local_clipboard_hash != local_clip_message.hash {
		    post_text(config.clone(), local_clip_message.encrypt_aes_256_cbc(&key), local_clip_message.hash.clone().as_str(), client.clone());
		    prev_local_clipboard_hash = local_clip_message.hash.clone();
		}

	    },
	    Err(err) => eprintln!("Error getting clipboard: {}", err)
	}

		
    }
}

fn get_text_hash(conf:Arc<Mutex<Config>>, client:Arc<Client>) -> String {
    let mut result = String::new();
    let response = client.get(form_url(conf.clone(), "/text_hash"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .send();
    match response{
	Ok(response) =>{
	    let token_header = response.headers().get("HASH").map(|value| value.to_str().unwrap_or_default());
	    match token_header{
		Some(value) => {result.push_str(value)},
		None => eprintln!("HASH header is absent from /test_hash endpoint")
	    }
	},
	Err(err) => eprintln!("Failed to send request to /text_hash endpoint because of: {}", err)
    }
    result
}

fn get_text(conf: Arc<Mutex<Config>>, client:Arc<Client>) -> Vec<u8> {
    let response = client.get(form_url(conf.clone(), "/text_get"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .send();
    let mut result:Vec<u8> = Vec::new();
    result = match response{
	Ok(resp) => match resp.bytes(){
	    Ok(bts) => bts.to_vec(),
	    Err(_) =>  vec![]
	},
	 Err(err) => vec![]
    };
    result
}

fn post_text(conf: Arc<Mutex<Config>>, encrypted: Vec<u8>, hash: &str, client:Arc<Client>) {
    let response = client.post(form_url(conf.clone(), "/text_post"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .header("HASH", hash)
        .body(encrypted)
        .send();
    match response{
	Ok(_) => (),
	Err(err) => eprintln!("Failed to post to /text_post because of {}", err)
    }  
}

fn post_file(conf: Arc<Mutex<Config>>, encrypted: Vec<u8>, file_name:String, client:Arc<Client>) {
    let response = client.post(form_url(conf.clone(), "/file_post"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
	.header("FILENAME", &file_name)
        .body(encrypted)
        .send();
    match response{
	Ok(_) => (),
	Err(err) => eprintln!("Failed to post to /file_post because of {}", err)
    }  
}

fn get_file(conf: Arc<Mutex<Config>>, client:Arc<Client>) -> FileMessage {
    let response = client.get(form_url(conf.clone(), "/file_get"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .body("")
        .send();
    let mut result_message:FileMessage;
    match response{
	Ok(payload) => {
	    let headers = payload.headers().clone();
	    let file_name = headers.get("FILENAME").map(|value| value.to_str().unwrap_or_default()).unwrap_or_default();
	    let encrypted_data = payload.bytes().unwrap().to_vec();
	    result_message = FileMessage::new(file_name.to_string(), encrypted_data);
	},
	Err(err) => {
	    result_message = FileMessage::new("".to_string(), Vec::new());
	    eprintln!("Failed to get to /file_get because of {}", err)
	}
    }
    result_message
}

fn form_url(conf: Arc<Mutex<Config>>, endpoint:&str) -> String {
    let mut result = String::new();
    result.push_str("http://");
    result.push_str(&conf.lock().unwrap().Host);
        result.push_str(endpoint);
    result
}

fn main() -> std::io::Result<()> {
    let config = fs::read_to_string("config.json")
        .expect("Should have been able to read the file");
    let conf:Config =  serde_json::from_str(&config).unwrap();
    let config_mutex = Arc::new(Mutex::new(conf.clone()));
    let config_mutex_copy = Arc::clone(&config_mutex);
    let http_client = Client::new();
    let client_arc = Arc::new(http_client);
    let client_arc_copy = Arc::clone(&client_arc);
    let scan_task = thread::spawn(move || {tui_scan(Arc::clone(&config_mutex.clone()), Arc::clone(&client_arc.clone()))}) ;
    let _clip_task = thread::spawn(move ||{watch_clipboard(config_mutex_copy, client_arc_copy)});
    scan_task.join().unwrap();
    _clip_task.join().unwrap();
    Ok(())
}
