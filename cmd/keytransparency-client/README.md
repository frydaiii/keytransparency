# Key Transparency Client

The Key Transparency client allows users to interact with the Key Transparency server to perform various operations related to key management.

## Installation

1. Install [Go 1.13+](https://golang.org/doc/install).
2. Install the client:
   ```
   GO111MODULE=on go get github.com/google/keytransparency/cmd/keytransparency-client
   ```

## Usage

The Key Transparency client provides the following commands:

### View Keys

```
keytransparency-client get <email> --kt-url <server-url>
```

### Publish Keys

```
keytransparency-client post <email> --kt-url <server-url> --data <key-data>
```

### Check Key History

```
keytransparency-client history <email> --kt-url <server-url>
```

### Check Key Expiration Status

The `check-expiration` command allows users to check if their keys are expired or will expire soon:

```
keytransparency-client check-expiration <email> --kt-url <server-url>
```

Options:
- `--warning-days value`: Number of days before expiration to show warnings (default: 30)

Example output:
```
✅ Key ID 12345678 is valid (expires in 180 days on 2025-11-07)
⚠️ WARNING: Key ID 87654321 will expire in 15 days (on 2025-05-26)
⚠️ KEY EXPIRED: Key ID 10101010 expired on 2025-04-01

Please rotate any keys that are expired or will expire soon.
Use 'keytransparency-client authorized-keys create-keyset' to create new keys.
```

### Key Management

Create a new set of update signing keys:
```
keytransparency-client authorized-keys create-keyset --password=<password>
```

List your authorized keys:
```
keytransparency-client authorized-keys list-keyset --password=<password>
```

## Configuration

The client can be configured through flags or a configuration file. A configuration file is located at `$HOME/.keytransparency.yaml` by default.

### Common Flags

- `--kt-url`: URL of Key Transparency server (default "sandbox.keytransparency.dev:443")
- `--directory`: Directory within the KT server (default "default")
- `--insecure`: Skip TLS checks
- `--config`: Config file (default "$HOME/.keytransparency.yaml")
- `--verbose`: Print more information
- `--timeout`: Request timeout (default 15s)
