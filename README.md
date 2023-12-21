# Tool for securely synchronizing clipboards of different devices

## Configuration
```json
{
  "Host":"127.0.0.1:6969",
  "Token":"ExampleAccessToken",
  "Passkey":"PasswordForAESEncryption"
}
```

* Host:
  Server - it should be 0.0.0.0:{port} <br/>
  Client(s) - it should be {serverip}:{port}
* Token - `should be the same` on server and client
* Passkey:
  Server - it `should be empty` string <br/>
  Client(s) - it `should contain a secret`

 ## Usage
 * Add your settings into `config.json` file
 * Run server app on server
 * Run client app on client
