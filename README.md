# Native Passkeys Development Tool
This is a tool to help with Native Passkeys development. It currently handles the following:
- Native Passkey Register
  - Calls `/passkey/register` and then `/oath/token`
- Native Passkey Challenge
  - Calls `/passkey/challenge` and then `/oath/token`

Much of the Webauthn code is based on the following tool: https://github.com/abbaspour/auth0-native-passkey-bash

### Setup
```shell
./scripts/bootstrap.sh
```
This will create `private-key.pem`, `config.json` and `users.json` files. Be sure to fill in your tenant details in the `config.json` file before proceeding.

## config.json

This file contains your tenant details.
```json
{
  "domain": "<tenant_domain>",
  "realm": "<connection_name>",
  "clientID": "<client_id>>",
  "email": "<identifier ex: email@email.com>",
  "organization": "<organization_id_or_name>",
  "useOrganization": false,
  "debug": false
}
```

## users.json

This file will keep track of your registered users and passkeys. You can also manually enter details by collecting the `credential_id` from the mongo database, so that you can use existing passkeys within your developement envrionment.
```json
[
  {
      "credential_id": "<passkey_credential_id>",
      "display_name": "<identifier ex: email@email.com>",
      "id": "<passkey_user_handle>",
      "name": "<identifier ex: email@email.com>"
  },
  ...
]
```

## Usage

### Register
```sh
  go run . -purpose register
```

Override identifiers from config:
```shell
 go run . -purpose register -email email@test.com
```

### Challenge
```sh
  go run . -purpose challenge
```

Override identifiers from config:
```shell
 go run . -purpose challenge -email email@test.com
```

## Make script executable from terminal
If you don't want to `cd` into this repo each time to run the script, execute the following commands.
Note your'll need admin privs on your mac.
```shell
## Build executable
go build .

## OPTIONAL: Rename if you want
sudo mv passkey_tool nptool

## Move to bin
sudo mv nptool /usr/local/bin/
```
After these command you should be able to run the script from any location with
```shell
nptool -purpose register
```