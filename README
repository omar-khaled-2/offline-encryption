# VideoCLI

VideoCLI is a command-line tool for handling video encryption using certificates and access keys.

## Features
- **Generate Certificate**: Create a new certificate for encryption.
- **Generate Access Key**: Generate an access key using an existing certificate.
- **Encrypt Video**: Encrypt a video file with a certificate.

## Installation

Ensure you have Rust installed. Then, clone the repository and build the project:

```sh
git clone <repo_url>
cd encryption
cargo build --release
```

## Usage

Run the CLI with the available commands:

### 1. Generate a Certificate
```sh
encryption generate-certificate -p <password> -o <certificate_file>
```
Example:
```sh
encryption generate-certificate -p mysecret -o mycert.pem
```

### 2. Generate an Access Key
```sh
encryption generate-access-key -k <key> -c <certificate_file> -p <password>
```
Example:
```sh
encryption generate-access-key -k mykey -c mycert.pem -p mysecret
```

### 3. Encrypt a Video
```sh
encryption encrypt-video -c <certificate_file> -p <password> -v <video_file> -o <output_file>
```
Example:
```sh
encryption encrypt-video -c mycert.pem -p mysecret -v input.mp4 -o encrypted.mp4
```

## Dependencies
This project uses the following dependencies in `Cargo.toml`:

```toml
[package]
name = "encryption"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8.4"
base64 = "0.22.1"
clap = { version = "4.4", features = ["derive"] }
ctr = "0.9.2"
p12 = "0.6.3"
p12-keystore = "=0.1.4"
rand = "0.8.0"
rcgen = "0.13.2"
rsa = "0.9.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10.8"
zeroize = "1.8.1"

[dependencies.uuid]
version = "1.16.0"
# Lets you generate random UUIDs
features = [
    "v4",
]
```

## License
This project is open-source and available under the MIT License.

---

Contributions and feedback are welcome! 🚀

