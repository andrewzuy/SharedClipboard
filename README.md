# Secure Clipboard Synchronizer

A Rust-based tool for securely synchronizing clipboards across different devices using AES-256-CBC encryption and TLS/SSL.

## Features
- **AES-256-CBC Encryption**: Military-grade encryption for clipboard data
- **TLS/SSL Support**: Secure communication with optional certificate validation
- **TUI Interface**: Clean terminal user interface for file/text transfer
- **Cross-Platform**: Works across different devices and operating systems
- **File Transfer**: Supports sending and receiving encrypted files
- **Real-time Sync**: Automatically syncs clipboard content between devices

## Architecture

### Server Components (`src/server.rs`)
- REST API endpoints for clipboard operations
- Token-based authentication
- Shared state management for text and file data
- Optional SSL/TLS with self-signed certificates

### Client Components (`src/client.rs`)
- TUI interface for clipboard monitoring
- File send/receive operations
- Automatic clipboard synchronization
- Encryption/decryption using AES-256-CBC

### Encryption Module (`src/aes_encryption.rs`)
- AES-256-CBC implementation
- SHA256-based key derivation
- IV generation using /dev/urandom
- Block cipher encryption/decryption

## Configuration

### server_config.json
```json
{
  "Host":"0.0.0.0:6969",
  "Token":"58ef27a7-5777-4bf9-8a64-08115bdf72cc"
}
```
- `Host`: Server address (e.g., "0.0.0.0:6969" or "localhost:6969")
- `Token`: Authorization token (generate using `uuidgen` or manually)
- SSL certificates (`key.pem`, `cert.pem`) are optional

### client_config.json
```json
{
  "Host":"https://localhost:6969",
  "Token":"58ef27a7-5777-4bf9-8a64-08115bdf72cc",
  "Passkey":"PasswordForAESEncryption"
}
```
- `Host`: Server URL (includes protocol)
- `Token`: Must match server token
- `Passkey`: Used for AES-256 key derivation (keep secure!)

## Setup

### Prerequisites
- Rust installed (`cargo`)
- SSL certificates (`key.pem`, `cert.pem`) for HTTPS

### Quick Start
1. **Generate Token** (on Linux/macOS):
   ```bash
   uuidgen
   ```

2. **Configure**: Update config files with your settings

3. **Build**:
   ```bash
   cargo build
   ```

4. **Run Server** (first):
   ```bash
   cargo run --bin server
   ```

5. **Run Client** (second):
   ```bash
   cargo run --bin client
   ```

## Usage

### Send File
1. Drag and drop a file into the client TUI OR
2. Type file path and press Enter

### Receive File
- Press `Ctrl+R` in client TUI

### Quit
- Press `Ctrl+C`

### TUI Controls
- **Type**: Enter text to send
- **Drag & Drop**: Drop files directly
- **Path Input**: Type file path and press Enter
- **Ctrl+R**: Trigger file receive
- **Ctrl+C**: Quit application

## Endpoints

### `/text_hash` (GET)
- Retrieves current clipboard hash
- Returns `HASH` header with clipboard content hash

### `/text_get` (GET)
- Fetches encrypted clipboard content
- Returns clipboard data as binary

### `/text_post` (POST)
- Sends encrypted clipboard content
- Requires `HASH` header

### `/file_get` (GET)
- Retrieves encrypted file
- Returns `FILENAME` header with file name

### `/file_post` (POST)
- Sends encrypted file
- Requires `FILENAME` header

## Dependencies

```toml
[dependencies]
actix-web = {version = "4.4.0", features = ["openssl"]}  # Web server
aes = "0.8.3"                                            # Encryption
bincode = "1.3.3"                                        # Serialization
clipboard = "0.5.0"                                      # Clipboard access
futures = "0.3.29"                                       # Async operations
rand = "0.8.5"                                           # Random number generation
serde = { version = "1.0.192", features = ["derive"]}    # JSON serialization
serde_json = "1.0.108"                                   # JSON parsing
sha256 = "1.4.0"                                         # Hashing
reqwest = { version = "0.11", features = ["blocking"] }  # HTTP client
tokio = { version = "1", features = ["full"] }           # Async runtime
openssl = "0.10.62"                                      # TLS/SSL
crossterm = {version = "0.27.0", features = ["bracketed-paste"]}  # TUI
```

## Security Notes
- Token must be identical on server and all clients
- Passkey is used to derive AES encryption key - keep it secret
- SSL certificates provide additional encryption in transit
- Token is for authorization only, not encryption
