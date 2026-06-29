# PQC TLS Demo

`pqc_demo` minh họa một kênh liên lạc client–server lấy cảm hứng từ TLS, sử dụng các thuật toán hậu lượng tử của [liboqs](https://github.com/open-quantum-safe/liboqs) và các primitive đối xứng của OpenSSL.

> **Lưu ý:** đây là dự án học tập, không phải một triển khai TLS/HTTPS tương thích tiêu chuẩn và không nên dùng để bảo vệ dữ liệu thật.

## Tính năng chính

- Trao đổi bí mật bằng **ML-KEM-768**.
- Xác thực transcript bắt tay bằng chữ ký **ML-DSA-65**.
- Theo dõi transcript bằng **SHA-256**.
- Xác nhận hai phía bằng Finished message, **HKDF-SHA256** và **HMAC-SHA256**.
- Dẫn xuất khóa phiên 256 bit bằng **HKDF-SHA256**.
- Mã hóa application data bằng **AES-256-GCM**.
- Truyền dữ liệu qua TCP trên `127.0.0.1:8080`.

## Luồng hoạt động

```text
Client                                              Server
  |                                                    |
  |-- ClientHello: ML-KEM public key ----------------->|
  |<-- ServerHello: ML-KEM ciphertext -----------------|
  |<-- Certificate: raw ML-DSA public key -------------|
  |<-- CertificateVerify: signature(transcript hash) --|
  |<-- Finished: HMAC(transcript hash) ----------------|
  |-- Finished: HMAC(transcript hash) ---------------->|
  |                                                    |
  |-- AES-256-GCM application record ----------------->|
  |              "Hello Secure PQC!"                   |
```

Client tạo cặp khóa ML-KEM tạm thời và gửi public key. Server encapsulate để tạo ciphertext cùng shared secret; client decapsulate ciphertext để thu được cùng shared secret. Hai phía kiểm tra transcript bắt tay và Finished message trước khi dẫn xuất cùng một khóa AES.

Handshake message có header 4 byte:

```text
message_type (1 byte) | body_length (3 byte) | body
```

Application record có định dạng thử nghiệm:

```text
content_type (1) | version (2) | length (2) | IV (12) | tag (16) | ciphertext
```

## Yêu cầu hệ thống

- Linux hoặc môi trường POSIX có TCP socket.
- Trình biên dịch C hỗ trợ C11 (GCC hoặc Clang).
- `make`, `pkg-config` và CMake (nếu tự build liboqs).
- OpenSSL **3.x** và header phát triển.
- liboqs có bật `ML-KEM-768` và `ML-DSA-65`.

Ví dụ cài các công cụ nền trên Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config libssl-dev
```

Nếu repository có thư mục `liboqs/` ở cấp bên cạnh `pqc_demo/`, có thể build và cài thư viện như sau:

```bash
cmake -S liboqs -B liboqs/build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build
sudo cmake --install liboqs/build
sudo ldconfig
```

Kiểm tra dependency đã được tìm thấy:

```bash
pkg-config --modversion liboqs openssl
```

Nếu `pkg-config` không tìm thấy liboqs được cài vào `/usr/local`, thử:

```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## Build

Các lệnh dưới đây được chạy từ thư mục `pqc_demo`:

```bash
cd pqc_demo
make
```

Hai chương trình chính được tạo tại:

```text
build/secure_server
build/secure_client
```

Build lại từ đầu:

```bash
make clean
make
```

Có thể thay compiler hoặc cờ biên dịch:

```bash
make CC=clang CFLAGS="-Wall -Wextra -O2"
```

## Chạy demo đầy đủ

Chương trình sử dụng đường dẫn tương đối tới thư mục `keys/`, vì vậy hãy chạy cả hai terminal từ `pqc_demo`.

Terminal 1 — khởi động server:

```bash
cd pqc_demo
./build/secure_server
```

Terminal 2 — khởi động client:

```bash
cd pqc_demo
./build/secure_client
```

Khi thành công, hai phía in ra cùng một AES key; server xác minh Client Finished và giải mã được:

```text
[OK] Decrypted message: Hello Secure PQC!
```

Server xử lý một client rồi thoát. Muốn chạy lại, hãy khởi động server trước rồi chạy client.

## Khóa ML-DSA của server

Repository hiện có sẵn hai file khóa nhị phân:

```text
keys/server_mldsa_public.key
keys/server_mldsa_secret.key
```

Để tạo cặp khóa mới:

```bash
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

Lệnh tạo khóa dùng đường dẫn tương đối `../keys`, nên bước chạy từ thư mục `tools/` là bắt buộc. Không công khai hoặc commit secret key mới nếu repository được chia sẻ.

## Các demo thành phần

`Makefile` mặc định chỉ build secure client/server. Có thể build riêng các ví dụ thuật toán như sau (từ `pqc_demo`):

```bash
mkdir -p build

cc -Wall -Wextra -O2 demo/kem_demo.c \
  -o build/kem_demo \
  $(pkg-config --cflags --libs liboqs openssl)

cc -Wall -Wextra -O2 demo/sig_demo.c \
  -o build/sig_demo \
  $(pkg-config --cflags --libs liboqs openssl)

cc -Wall -Wextra -O2 demo/aes_demo.c \
  -o build/aes_demo $(pkg-config --cflags --libs openssl)
```

Chạy:

```bash
./build/kem_demo
./build/sig_demo
./build/aes_demo
```

Các cặp `network/server.c` + `network/client.c` và `network/kem_server.c` + `network/kem_client.c` là những bước thử nghiệm đơn giản hơn dẫn tới secure demo hoàn chỉnh.

## Cấu trúc thư mục

```text
pqc_demo/
├── Makefile                 # Build secure client và server
├── demo/                    # Demo độc lập: ML-KEM, ML-DSA, AES-GCM, HKDF
├── include/                 # Public header của các module
├── keys/                    # Cặp khóa ML-DSA nhị phân của server
├── network/                 # TCP, KEM và secure client/server
├── src/                     # Handshake, transcript, Finished, record và crypto
└── tools/                   # Công cụ tạo cặp khóa ML-DSA
```

Các module chính:

| Module | Vai trò |
|---|---|
| `tls_handshake` | Encode, gửi và nhận handshake message |
| `tls_transcript` | Băm liên tục các handshake message bằng SHA-256 |
| `tls_finished` | Dẫn xuất Finished key và tính HMAC xác nhận transcript |
| `kdf` | Dẫn xuất khóa phiên bằng HKDF-SHA256 |
| `aes_gcm` | Mã hóa và xác thực bằng AES-256-GCM |
| `tls_record` | Đóng gói và giải mã application record thử nghiệm |
| `sig_utils` | Đọc khóa ML-DSA từ file |
| `common` | Gửi/nhận đủ số byte và in dữ liệu hexadecimal |

## Xử lý lỗi thường gặp

### `Package liboqs was not found`

Đảm bảo liboqs đã được cài và `PKG_CONFIG_PATH` chứa thư mục có `liboqs.pc`. Dùng lệnh sau để kiểm tra:

```bash
pkg-config --cflags --libs liboqs
```

### Lỗi khi nạp shared library

Nếu chương trình báo không tìm thấy `liboqs.so`, chạy `sudo ldconfig` sau khi cài hoặc thêm `/usr/local/lib` vào `LD_LIBRARY_PATH`.

### `fopen: No such file or directory`

Secure client/server phải được chạy từ thư mục `pqc_demo`, nơi có thư mục `keys/`. Kiểm tra:

```bash
ls -l keys/server_mldsa_*.key
```

### `bind: Address already in use`

Một tiến trình khác đang dùng cổng `8080`. Dừng tiến trình/server cũ rồi chạy lại.

### `connect: Connection refused`

Khởi động `secure_server` trước `secure_client` và kiểm tra cả hai đang dùng `127.0.0.1:8080`.

## Giới hạn bảo mật

Dự án chỉ mô phỏng một phần ý tưởng của TLS:

- Không dùng state machine, wire format hoặc key schedule chuẩn TLS 1.3.
- “Certificate” chỉ chứa raw ML-DSA public key; không có X.509, CA, hostname verification hoặc trust store.
- Client nhận public key xác thực ngay trong cùng kết nối và chưa pin khóa, vì vậy chưa chống được kẻ trung gian chủ động.
- Record chưa có sequence number, nonce derivation, AAD, chống replay, key update hoặc alert protocol như TLS thật.
- AES key được in ra terminal để quan sát demo; phần mềm thực tế không được log key bí mật.
- Secret key mẫu nằm trong repository và chỉ phù hợp cho thử nghiệm cục bộ.
- Server hiện chỉ phục vụ một kết nối và client/server dùng địa chỉ, cổng, thông điệp cố định trong mã nguồn.

Để xây dựng ứng dụng thực tế, hãy dùng một thư viện TLS đã được kiểm định và cấu hình hỗ trợ thuật toán hậu lượng tử phù hợp thay vì mở rộng trực tiếp protocol demo này.
