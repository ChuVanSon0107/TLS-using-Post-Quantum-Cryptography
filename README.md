# PQC TLS Demo

`pqc_demo` is an educational client-server secure channel inspired by TLS. It combines post-quantum key exchange and authentication from [liboqs](https://github.com/open-quantum-safe/liboqs) with symmetric primitives from OpenSSL.

This is not a standards-compliant TLS/HTTPS implementation. Do not use it to protect real data.

## Features

- Post-quantum key exchange with **ML-KEM-768**.
- Server authentication with **ML-DSA-65**.
- A raw ML-DSA public key carried in a demo `Certificate` message.
- Handshake transcript tracking with **SHA-256**.
- Server and client `Finished` verification with **HKDF-SHA256** and **HMAC-SHA256**.
- Application key schedule that derives separate client/server AES keys and IVs.
- Encrypted application records with **AES-256-GCM**.
- AES-GCM nonce derived from a per-direction static IV and record sequence number.
- Record header authentication through AES-GCM AAD.
- Local TCP transport on `127.0.0.1:8080`.

## Protocol Flow

```text
Client                                                   Server
  |                                                        |
  |-- ClientHello: ML-KEM public key --------------------->|
  |<-- ServerHello: ML-KEM ciphertext ---------------------|
  |<-- Certificate: raw ML-DSA public key -----------------|
  |<-- CertificateVerify: signature(transcript hash) ------|
  |<-- Finished: HMAC(transcript hash) --------------------|
  |-- Finished: HMAC(transcript hash) -------------------->|
  |                                                        |
  |-- AES-256-GCM application record --------------------->|
  |<-- AES-256-GCM application record ---------------------|
```

The client generates an ephemeral ML-KEM key pair and sends the public key in `ClientHello`. The server encapsulates to that key, sends the ML-KEM ciphertext in `ServerHello`, and both sides arrive at the same shared secret.

The server then sends a raw ML-DSA public key in `Certificate` and signs the current transcript hash in `CertificateVerify`. Both sides verify `Finished` messages before deriving application traffic keys.

## Message Formats

Handshake messages use a compact 4-byte header:

```text
message_type (1 byte) | body_length (3 bytes) | body
```

Application records use this demo format:

```text
content_type (1 byte) | version (2 bytes) | length (2 bytes) | ciphertext | tag (16 bytes)
```

The record header is used as AES-GCM AAD. The IV is not sent on the wire. Each side derives a static IV from the key schedule, then computes the per-record nonce as:

```text
nonce = static_iv XOR sequence_number
```

Each traffic direction has its own key, IV, and sequence number:

- client-to-server: `client_key`, `client_iv`
- server-to-client: `server_key`, `server_iv`

## Requirements

- Linux or another POSIX-like environment with TCP sockets.
- GCC or Clang.
- `make` and `pkg-config`.
- OpenSSL 3.x development headers and libraries.
- liboqs built with ML-KEM-768 and ML-DSA-65 support.

On Ubuntu/Debian, the base packages are typically:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config libssl-dev
```

If you build liboqs from source:

```bash
cmake -S liboqs -B liboqs/build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build
sudo cmake --install liboqs/build
sudo ldconfig
```

Check that the dependencies are visible:

```bash
pkg-config --modversion liboqs openssl
```

If liboqs was installed under `/usr/local` and `pkg-config` cannot find it:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## Build

Run the build from the `pqc_demo` directory:

```bash
cd pqc_demo
make
```

This creates:

```text
build/secure_server
build/secure_client
```

To rebuild from scratch:

```bash
make clean
make
```

You can also override the compiler:

```bash
make CC=clang CFLAGS="-Wall -Wextra -O2"
```

## Run

The programs use relative paths to the `keys/` directory, so run both commands from `pqc_demo`.

Terminal 1:

```bash
cd pqc_demo
./build/secure_server
```

Terminal 2:

```bash
cd pqc_demo
./build/secure_client
```

On success, both peers complete the post-quantum handshake, derive application keys, exchange encrypted application data, and print decrypted messages such as:

```text
[OK] Decrypted message: Hello Secure PQC from Client!
[OK] Decrypted message: Hello Secure PQC from Server!
```

The server handles one client connection and then exits. Start the server again before rerunning the client.

## Server ML-DSA Keys

The demo expects these binary key files:

```text
keys/server_mldsa_public.key
keys/server_mldsa_secret.key
```

To generate a new pair:

```bash
cd pqc_demo
mkdir -p build
cc -Wall -Wextra -O2 \
  $(pkg-config --cflags liboqs) \
  tools/generate_dsa_keypair.c \
  -o build/generate_dsa_keypair \
  $(pkg-config --libs liboqs openssl)

cd tools
../build/generate_dsa_keypair
cd ..
```

The key generator writes to `../keys`, so it must be run from `pqc_demo/tools`. Do not publish or commit newly generated secret keys in a shared repository.

## Project Layout

```text
pqc_demo/
├── Makefile                 # Builds secure client and server
├── demo/                    # Standalone ML-KEM, ML-DSA, AES-GCM, and HKDF demos
├── include/                 # Public headers
├── keys/                    # Demo ML-DSA server key pair
├── network/                 # TCP demos and secure client/server
├── src/                     # Handshake, transcript, Finished, record, and crypto code
└── tools/                   # ML-DSA key generation tool
```

Main modules:

| Module | Purpose |
|---|---|
| `tls_handshake` | Encodes, sends, and receives handshake messages |
| `tls_transcript` | Hashes handshake messages with SHA-256 |
| `tls_finished` | Computes Finished verify data with HKDF/HMAC |
| `tls_key_schedule` | Derives client/server application keys and IVs |
| `aes_gcm` | AES-256-GCM encryption/decryption with optional AAD |
| `tls_record` | Demo encrypted record layer with sequence-based nonces |
| `sig_utils` | Loads ML-DSA keys from files |
| `common` | Reliable send/receive helpers and hex printing |

## Standalone Demos

The default `Makefile` builds only the secure client and server. You can compile individual demos from `pqc_demo`:

```bash
mkdir -p build

cc -Wall -Wextra -O2 demo/kem_demo.c \
  -o build/kem_demo \
  $(pkg-config --cflags --libs liboqs openssl)

cc -Wall -Wextra -O2 demo/sig_demo.c \
  -o build/sig_demo \
  $(pkg-config --cflags --libs liboqs openssl)

cc -Wall -Wextra -O2 demo/aes_demo.c \
  -o build/aes_demo \
  $(pkg-config --cflags --libs openssl)

cc -Wall -Wextra -O2 demo/hkdf_demo.c \
  -o build/hkdf_demo \
  $(pkg-config --cflags --libs openssl)
```

Run them with:

```bash
./build/kem_demo
./build/sig_demo
./build/aes_demo
./build/hkdf_demo
```

## Troubleshooting

### `Package liboqs was not found`

Make sure liboqs is installed and that `PKG_CONFIG_PATH` includes the directory containing `liboqs.pc`.

```bash
pkg-config --cflags --libs liboqs
```

### Shared library load errors

If the program cannot find `liboqs.so`, run `sudo ldconfig` after installing liboqs, or add `/usr/local/lib` to `LD_LIBRARY_PATH`.

### `fopen: No such file or directory`

Run `secure_server` and `secure_client` from `pqc_demo`, where the `keys/` directory is located.

```bash
ls -l keys/server_mldsa_*.key
```

### `bind: Address already in use`

Another process is using port `8080`. Stop the old server or change the port in both client and server.

### `connect: Connection refused`

Start `secure_server` before `secure_client` and confirm that both use `127.0.0.1:8080`.

## Security Limitations

This project intentionally implements only a small learning-oriented subset of TLS ideas:

- It is not wire-compatible with TLS 1.3.
- It does not implement the TLS 1.3 state machine, alerts, extensions, cipher suite negotiation, or key update.
- The `Certificate` message carries a raw ML-DSA public key, not an X.509 certificate chain.
- There is no CA validation, hostname verification, trust store, or robust public-key pinning model.
- `CertificateVerify` currently signs the transcript hash directly instead of the exact TLS 1.3 domain-separated structure.
- The key schedule is demo-specific and not the TLS 1.3 key schedule.
- Replay protection, rekeying, fragmentation policy, and traffic limits are minimal.
- The sample server key is included for local testing only.
- The server handles one connection and uses fixed address, port, algorithms, and demo messages.

For real applications, use a reviewed TLS library with appropriate post-quantum support instead of extending this demo protocol directly.
