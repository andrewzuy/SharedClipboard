use std::sync::mpsc::{channel, Sender, Receiver};
use std::io::{stdin};
use std::sync::{Arc, Mutex};
extern crate clipboard;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use std::{fs, thread,time, thread::JoinHandle};
use serde::{Deserialize};
use reqwest::blocking::Client;
mod aes_encryption;
use std::fs::File;
use std::path::Path;
use crate::aes_encryption::aes_encryption::{AesEngine, Message, FileMessage};
use std::io::{stdout, Write};
use std::time::{Duration};
use crossterm::event::{KeyEventKind, EnableBracketedPaste};
use crossterm::{
    ExecutableCommand, QueueableCommand,
    execute,
    cursor,
    terminal::{self, enable_raw_mode, disable_raw_mode},
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor, PrintStyledContent},
    event::{poll, read, Event, KeyEvent, KeyCode, KeyModifiers, ModifierKeyCode},
};

#[derive(Debug,Deserialize, Clone)]
struct Config{
    Host:String,
    Token:String,
    Passkey:String
}

fn render_ui(config:Arc<Mutex<Config>>, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>){
    let key = aes_encryption::aes_encryption::get_key(config.clone().lock().unwrap().clone().Passkey);
    let mut stdout = stdout();
    let (mut width, mut heights) = terminal::size().unwrap();
    let mut filename = String::new();
    let mut temp = String::new();
    let mut  quit = false;
    let mut changes = true;
    _ = enable_raw_mode();
    execute!(stdout, EnableBracketedPaste).unwrap_or_default();
    _= stdout.execute(terminal::Clear(terminal::ClearType::All));
    while !quit{
	if  poll(Duration::from_millis(100 as u64)).unwrap(){
	    match read(){
		Ok(ev) => match ev{
		    Event::Resize(w, h) => { width = w; heights = h; changes = true},
		    Event::Key(key_event) => {
			match key_event.code{
			    KeyCode::Char(x) => {
				if x == 'c' && key_event.modifiers.contains(KeyModifiers::CONTROL){
				     quit = true;
				}
				if x  == 'r' && key_event.modifiers.contains(KeyModifiers::CONTROL){
				    changes = true;
				    handle_receive_file(config.clone(), client.clone(), key.clone(), log.clone());
				} else if !key_event.modifiers.contains(KeyModifiers::CONTROL) {
				    temp.push(x);
				    changes = true;
				}
			    },
			    KeyCode::Backspace => {
			        changes = true;
				let len = temp.len();
				if len > 0{
				    temp.pop();
				} else {
				    temp.clear();
				}
			    },
			    KeyCode::Enter => {
				changes = true;
				filename = temp.clone();
				temp.clear();
				handle_sending_file(filename.clone(), config.clone(), client.clone(), key.clone(), log.clone());
			    },
			_ => ()
			}
		    },
		    
		    Event::Paste(path) => {
			changes = true;
			filename.clear();
			filename.push_str(&path);
			temp = filename.clone();
			match log.try_lock(){
			    Ok(mut res) =>{
				res.push(format!("Sending file: {}",filename.clone()))
			    },
			    Err(_) => ()
			}
			handle_sending_file(filename.clone(), config.clone(), client.clone(), key.clone(), log.clone());
		    }
		    _ => ()
		},
		Err(_) => ()
	    }   
	}
	if changes{
	    render_rectangle(width, heights, 0, 0);
	    render_header(width-1,heights,1,1,"Secure Clipboard",'░');
	    if heights > 6{
		render_header(width-1, heights,1,heights/2 -1,"Drag and drop a file or enter file path to send and hit enter,",'░');
		render_header(width-1, heights,1,heights/2,"CTRL + R to receive, CTRL + C to quit",'░');
    		render_text(1, heights/2 +1  , &format!("┆FILE PATH┆⇒{}", temp));
		render_header(width-1,heights,1,heights*3/4,"Log:",'░');
	    } if heights > 9{
		match log.try_lock(){
		    Ok(mut res) =>{
			let temp = String::new();
			render_text(1, heights*3/4 +1, &res.last().unwrap_or_else(||{&temp}));
			if res.len() > 2 {
			    render_text(1, heights*3/4 +2, &res.get(res.len()-2).unwrap_or_else(||{&temp}));
			    render_text(1, heights*3/4 +3, &res.get(res.len()-3).unwrap_or_else(||{&temp}));
			}
		    },
		    Err(_) => ()
		}

	    }
	    stdout.flush();
            changes = false;
	}
	thread::sleep(Duration::from_millis(100 as u64));
    }
    
    _ = disable_raw_mode();
    _= stdout.execute(terminal::Clear(terminal::ClearType::All));
    
}

fn handle_sending_file(filename:String, config:Arc<Mutex<Config>>, client:Arc<Client>, key:[u8;32], log:Arc<Mutex<Vec<String>>>){
	    let file_str = clear_up_path(filename.clone());
	    let file_path = Path::new(&file_str);
	    let file_open = std::fs::read(file_path);
	    match file_open{
		Ok(file) => {
		    let file_message = FileMessage::new(file_path.file_name().unwrap().to_str().unwrap().to_string(), file);
		    post_file(config.clone(), file_message.file.encrypt_aes_256_cbc(&key), file_message.filename.clone(), client.clone(), log.clone());
			match log.try_lock(){
			    Ok(mut res) => res.push(format!("File sent: {}", filename.clone())),
			    Err(_) => ()
			}
		},
		Err(err) => match log.try_lock(){
			    Ok(mut res) => res.push(format!("Failed to post the file because of: {}", err)),
			    Err(_) => ()
			}
	    }
}

fn handle_receive_file(config:Arc<Mutex<Config>>, client:Arc<Client>, key:[u8;32], log:Arc<Mutex<Vec<String>>>){
            match log.try_lock(){
			    Ok(mut res) => res.push("Getting a file...".to_string()),
			    Err(_) => ()
			}
            let encrypted_message = get_file(config.clone(),client.clone(), log.clone());
	    if encrypted_message.filename.len() > 0 {
		let encrypted_file = encrypted_message.clone().file.value;
		let file_decrypted = encrypted_message.file.decrypt_aes_256_cbc(encrypted_file, &key).value;
		let _ = fs::create_dir("shared");
		let mut path = Path::new("shared/");
		let mut file = File::create(path.join(encrypted_message.clone().filename)).unwrap();
		file.write_all(&file_decrypted);
		match log.try_lock(){
			    Ok(mut res) => res.push(format!("Received, decrypted and saved file: {}", encrypted_message.filename)),
			    Err(_) => ()
			}
	    }
}

fn render_header(width: u16, heights: u16, startw:u16, starth:u16, label:&str, fill:char){
    let mut stdout = stdout();
    for w in startw..width{
		    _ = stdout.queue(cursor::MoveTo(w as u16, starth as u16));
		    _ = stdout.queue(Print(fill));
    }
    if (label.len()/2usize) < width as usize/2 {
    let start_position = width/2 - (label.len()/2) as u16;
	_ = stdout.queue(cursor::MoveTo(start_position, starth as u16));
	 _ = stdout.queue(Print(label));
    }
}

fn render_text(width: u16, heights: u16, label:&str){
    let mut stdout = stdout();
    _ = stdout.queue(cursor::MoveTo(width, heights));
    _ = stdout.queue(Print(label));
}


fn render_rectangle(width: u16, heights: u16, startw:u16, starth:u16){
        let mut stdout = stdout();
    	for w in startw..width{
	    for h in starth..heights{
		if (w == startw) && (h == starth){
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('┌'));
		} else if( w == width-1) && (h == starth){
       		    _ =  stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('┐'));
		} else if( w == startw) && (h == heights -1){
       		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('└'));
		} else if( w == width -1 ) && (h == heights -1){
       		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('┘'));
		} else if (h == starth) && (w !=startw) && (w< width -1){
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('─'));
		} else if (h == heights -1 ) && (w !=startw) && (w< width -1){
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('─'));
		} else if w == width -1{
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('│'));
		} else if w == startw{
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('│'));
		} else {
		    _ = stdout.queue(cursor::MoveTo(w as u16,h as u16));
		    _ = stdout.queue(Print('·'));		    
		}
	    }
	}
}


fn clear_up_path(raw: String) -> String{
    let mut result = String::new();
    result.push_str(raw.trim().replace("/n","").replace("'","").trim());
    result
}

fn watch_clipboard(config:Arc<Mutex<Config>>, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>, tui_handler:&JoinHandle<()>){
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let key = aes_encryption::aes_encryption::get_key(config.clone().lock().unwrap().clone().Passkey);
    let mut prev_local_clipboard_hash = String::new();
    let mut prev_remote_clipboard_hash = String::new();
    let mut temp_vec:Vec<u8> = Vec::new();
    while !tui_handler.is_finished() {
        thread::sleep(time::Duration::from_secs(1));
        let tmp = ctx.get_contents();
	match tmp{
	    Ok(tmp) => {
		let mut flag = true;
		let local_clip_message = Message::new(tmp.as_bytes().to_vec());
		let new_remote_hash = get_text_hash(config.clone(), client.clone(), log.clone());
		if new_remote_hash != prev_remote_clipboard_hash{
		    let encrypted_text = get_text(config.clone(), client.clone());
		    let decrypted_text = local_clip_message.decrypt_aes_256_cbc(encrypted_text.clone(), &key);
		    temp_vec = encrypted_text.clone();
		    match String::from_utf8(decrypted_text.value){
			Ok(str) =>  ctx.set_contents(str).unwrap(),
			Err(err) => match log.try_lock(){
			    Ok(mut res) => res.push(format!("failed to parse decrypted text, {}", err)),
			    Err(_) => ()
			}
		    }
		    prev_remote_clipboard_hash = new_remote_hash;
		    flag = false;
		}
		if flag && prev_local_clipboard_hash != local_clip_message.hash {
		    post_text(config.clone(), local_clip_message.encrypt_aes_256_cbc(&key), local_clip_message.hash.clone().as_str(), client.clone(), log.clone());
		    prev_local_clipboard_hash = local_clip_message.hash.clone();
		}

	    },
	    Err(_) => {
		let new_remote_hash = get_text_hash(config.clone(), client.clone(), log.clone());
		if new_remote_hash != prev_remote_clipboard_hash{
		    let encrypted_text = get_text(config.clone(), client.clone());
		    let local_clip_message = Message::new(Vec::new());
		    let decrypted_text = local_clip_message.decrypt_aes_256_cbc(encrypted_text.clone(), &key);
		    temp_vec = encrypted_text.clone();
		    match String::from_utf8(decrypted_text.value){
			Ok(str) =>  ctx.set_contents(str).unwrap(),
			Err(err) => match log.try_lock(){
				Ok(mut res) => res.push(format!("failed to parse decrypted text, {}", err)),
				Err(_) => ()
			}
			}
		    }
		    prev_remote_clipboard_hash = new_remote_hash;
	    } // eprintln!("Error getting clipboard: {}", err)
	}	
    }
    println!("\r\n Quiting main thread...\n");
    
  }

fn get_text_hash(conf:Arc<Mutex<Config>>, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>) -> String {
    let mut result = String::new();
    let response = client.get(form_url(conf.clone(), "/text_hash"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .send();
    match response{
	Ok(response) =>{
	    let token_header = response.headers().get("HASH").map(|value| value.to_str().unwrap_or_default());
	    match token_header{
		Some(value) => {result.push_str(value)},
		None =>  match log.try_lock(){
			    Ok(mut res) => res.push(format!("HASH header is absent from /test_hash endpoint")),
			    Err(_) => ()
			}
	    }
	},
	Err(err) =>  match log.try_lock(){
			    Ok(mut res) => res.push(format!("Failed to send request to /text_hash endpoint because of: {}", err)),
			    Err(_) => ()
			}
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

fn post_text(conf: Arc<Mutex<Config>>, encrypted: Vec<u8>, hash: &str, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>) {
    let response = client.post(form_url(conf.clone(), "/text_post"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
        .header("HASH", hash)
        .body(encrypted)
        .send();
    match response{
	Ok(_) => (),
	Err(err) =>  match log.try_lock(){
			    Ok(mut res) => res.push(format!("Failed to post to /text_post because of {}", err)),
			    Err(_) => ()
			}
    }
}

fn post_file(conf: Arc<Mutex<Config>>, encrypted: Vec<u8>, file_name:String, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>) {
    let response = client.post(form_url(conf.clone(), "/file_post"))
        .header("TOKEN", conf.lock().unwrap().clone().Token)
	.header("FILENAME", &file_name)
        .body(encrypted)
        .send();
    match response{
	Ok(_) => (),
	Err(err) =>  match log.try_lock(){
			    Ok(mut res) => res.push(format!("Failed to post to /file_post because of {}", err)),
			    Err(_) => ()
			}
    }
}

fn get_file(conf: Arc<Mutex<Config>>, client:Arc<Client>, log:Arc<Mutex<Vec<String>>>) -> FileMessage {
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
	     match log.try_lock(){
			    Ok(mut res) => res.push(format!("Failed to get to /file_get because of {}", err)),
			    Err(_) => ()
			}
	}
    }
    result_message
}

fn form_url(conf: Arc<Mutex<Config>>, endpoint:&str) -> String {
    let mut result = String::new();
    let host = &conf.lock().unwrap().Host.clone();
    if !host.contains("://"){
	result.push_str("http://");
    }
    result.push_str(host);
    result.push_str(endpoint);
    result
}

fn main() {
    let config = fs::read_to_string("client_config.json")
        .expect("Should have been able to read the file");
    let conf:Config =  serde_json::from_str(&config).unwrap();
    let config_mutex = Arc::new(Mutex::new(conf.clone()));
    let log:Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let config_mutex_copy = Arc::clone(&config_mutex);
    let cert_file = std::fs::read("cert.pem");
    let cert: reqwest::Certificate;
    let http_client:reqwest::blocking::Client;
    match cert_file {
	Ok(file) => {
	    cert = reqwest::Certificate::from_pem(file.as_slice()).unwrap();
	    http_client = Client::builder().add_root_certificate(cert).build().unwrap();
	},
	Err(err) => {
	    http_client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();
	    log.lock().unwrap().push("Ignoring certificate errors because cert.pem file is not provided.".to_string())
	}
    }
    let client_arc = Arc::new(http_client);
    let client_arc_copy = Arc::clone(&client_arc);

    let _tui_task = thread::spawn(move || {render_ui(Arc::clone(&config_mutex.clone()), Arc::clone(&client_arc.clone()), log2)});
    let _clip_task = thread::spawn(move ||{watch_clipboard(config_mutex_copy, client_arc_copy, log, &_tui_task)});
    _clip_task.join().unwrap();
}
