# age-plugin-keystore

An [age](https://github.com/FiloSottile/age) plugin that stores X25519 or Hybrid
Post-Quantum private keys in Linux Keyrings using the Secret Service D-Bus API.

## Overview

`age-plugin-keystore` integrates age encryption with Linux keyrings that uses
[freedesktop Secret Service D-Bus
API](https://specifications.freedesktop.org/secret-service/latest/) (like the
GNOME Keyring), allowing you to:

- Generate X25519 key pairs with private keys stored securely in keyring
- Generate mlkem768x25519 Hybrid Post-Quantum key with private keys stored
  securely in keyring
- Encrypt files to keystore recipients
- Decrypt files using keys retrieved from the keyring automatically

## Rationale

Ideally, encryption and decryption operations should be performed within a
secure enclave, an isolated hardware-protected environment that shields
cryptographic operations from the rest of the system. However, Linux user
keyrings provide a reasonable alternative for lighter security requirements,
offering kernel-managed key storage without the need for expensive hardware
security modules or physical tokens.

The keyring offers several advantages over storing keys directly on disk. Keys
stored in the keyring are tied to user authentication, they become accessible
only after login. Unlike plaintext files that persist indefinitely and may be
inadvertently copied through backups or synchronization, keyring-stored keys
exist only in kernel memory and never touch the filesystem in unencrypted form.

This protection model emphasizes defense against the remote threat scenario: an
attacker who gains access to your repository (through a server breach, backup
leak, or misconfigured permissions) will find only encrypted data they cannot
decrypt. The keys remain in the keyring on your local machine, separate from the
encrypted content.

It is important to understand the limitations of this approach. A malicious
process running under your user account on the same machine can potentially
access the keyring and decrypt your secrets. While a true hardware secure
enclave offers stronger protection against such local attacks, the added
complexity and cost make it impractical for many use cases. The Linux keyring
strikes a pragmatic balance as it defends well against remote threats and casual
local snooping, while accepting that a fully compromised local environment
remains difficult to protect against without specialized hardware and systems.

## Prerequisites

- Go 1.22 or later
- GNOME Keyring or another Secret Service API implementation

## Installation

```bash
go install github.com/arouene/age-plugin-keystore@latest
```

Or build from source:

```bash
git clone https://github.com/arouene/age-plugin-keystore
cd age-plugin-keystore
go build -o age-plugin-keystore .
```

Make sure the binary is in your `PATH` for age to find it automatically:

```bash
cp age-plugin-keystore ~/.local/bin/
# or
sudo cp age-plugin-keystore /usr/local/bin/
```

## Usage

### Generate a New Key

```bash
age-plugin-keystore -g
```

This will:
1. Generate a new X25519 key pair
2. Generate a random 8-byte key ID
3. Store the private key associated to the key ID in a Keyring using the secret
   service API
4. Print the identity string (for identity files) and public key (recipient with
   embedded key ID)

Example output:
```
# key ID: a1b2c3d4e5f6g7h8
age1...
AGE-PLUGIN-KEYSTORE-1...
```

This generate a separate identity, it means that the recipient is a generic
X25519 public key, and can be used without this plugin installed, useful if you
want to share it. But the decryption needs this plugin to be installed.

Save the identity string to a file:
```bash
age-plugin-keystore -g > identity.txt 2> recipient.txt
```

For Hybrid Post-Quantum keys, use the `-pq` option
```bash
age-plugin-keystore -g -pq >> identity.txt 2>> recipient.txt
```

### Encrypt a File

Use the public key (recipient) printed during key generation:

```bash
age -r age1... plaintext.txt > encrypted.age

# or

age -R recipient.txt plaintext.txt > encrypted.age
```

### Decrypt a File

Use the identity file created during key generation:

```bash
age -d -i identity.txt encrypted.age > plaintext.txt
```

The plugin will automatically retrieve the private key from the secret service.

### List Stored Keys

List all stored keys in your keystore.

```bash
age-plugin-keystore -l
```

### Delete a Key

This will delete the stored key in your keystore.

```bash
age-plugin-keystore -d YOUR_KEY_ID
```

## Security Considerations

- **Private Key Storage**: Private keys are stored in a Keyring, implementation
  varies but generally the private key is encrypted at rest
- **Key Access**: Keys are accessible to any process running as the same user
  when the keyring is unlocked
- **Keyring Unlocking**: The keyring is typically unlocked automatically when
  you log in
- **No Passphrases**: Unlike standard age keys, keystore keys are protected by
  the keyring's authentication, not individual passphrases

## File Format

### Recipient Format

```
age1<bech32-encoded-data>
```

Where the encoded data contains: `X25519-public-key`

### Identity Format

```
AGE-PLUGIN-KEYSTORE-1<bech32-encoded-data>
```

Where the encoded data contains: `key-ID`

In the keystore is stored the standard private key, identified by the key ID:

```
AGE-SECRET-KEY-1<bech32-encoded-data>
```

## Development

### Building

```bash
go build -v ./...
```

### Testing

```bash
go test -v ./...
```

Integration tests

```bash
go test -tags=integration -v ./test/
```

### Project Structure

```
age-plugin-keystore/
├── main.go                     # Plugin entry point
├── go.mod                      # Go module definition
├── README.md                   # This file
├── LICENSE.md                  # MIT License
└── internal/
    └── keystore/               # GNOME Keyring integration
        ├── keystore.go
        └── keystore_test.go

```

## Dependencies

- Go standard library
- `filippo.io/age` - age encryption library and plugin framework
- `github.com/godbus/dbus/v5` - D-Bus bindings for native Secret Service communication

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [age](https://github.com/FiloSottile/age) - Simple, modern and secure encryption tool
- [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) - YubiKey plugin for age
- [awesome-age](https://github.com/FiloSottile/awesome-age) - Collection of age-related projects
