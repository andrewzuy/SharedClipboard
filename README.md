# Tool for securely synchronizing clipboards of different devices

## Configuration
### client_config.json
```json
{
  "Host":"https://localhost:6969",
  "Token":"58ef27a7-5777-4bf9-8a64-08115bdf72cc",
  "Passkey":"PasswordForAESEncryption"
}
```

### server_config.json
```json
{
  "Host":"0.0.0.0:6969",
  "Token":"58ef27a7-5777-4bf9-8a64-08115bdf72cc"
}
```
* As per token - it could be generated using `uuidgen` command in Linux or it can be generated manually.
The token should be the same on server and clients. It's not an encryption key - it's for authorization purpose only.
* The `Passkey` parameter in the `client_config.json` file is used to generate AES key, so keep it safe.

 ## Usage
 * Add your settings into `server_config.json` and `client_config.json` files
 * Run server app on server
 * Run client app on client
![tui](https://github.com/andrewzuy/SharedClipboard/assets/25224814/ef8b36a7-f177-4da6-9854-88f467ead7a1)
