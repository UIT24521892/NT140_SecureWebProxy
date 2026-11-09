# Capture và đọc lưu lượng — TLS-6

Chạy các lệnh tại gốc repo bằng Python ≥3.10 và Docker Compose. Windows dùng WSL theo spec; hoặc chạy trực tiếp Python trên Windows cho các entry point `.py`.

```bash
python3 scripts/capture.py http-demo 5 --demo http
python3 scripts/capture.py splice-demo 5 --demo splice
python3 scripts/capture.py bump-demo 5 --demo bump
# Nếu cần giải mã upstream bằng key log Squid 6 trong bản build này:
python3 scripts/capture.py bump-tls12-demo 5 --demo bump --upstream-tls12
# Cần THR-4 đã triển khai, icap đang chạy:
python3 scripts/capture.py icap-demo 5 --demo icap
# Capture thủ công, thực hiện probe ở terminal khác trong thời gian này:
make capture NAME=manual-demo SECS=30
```

Script từ chối ghi đè capture đã có, bật TLS key log tạm thời, khởi chạy sniffer chung network namespace với Squid, rồi gửi SIGINT cho tcpdump để hoàn tất pcap. Trong `finally`, nó phục hồi cấu hình key log và TLS mode ban đầu. Các lần capture/benchmark/test đổi trạng thái lab phải chạy tuần tự.

Kết quả trong `captures/`: `<name>.pcap`, `<name>.txt` (tóm tắt tcpdump thật), `<name>.md`, và file `*.client.keys`/`*.squid.keys` khi có TLS secrets. ICAP demo từ chối chạy nếu dịch vụ icap chưa tồn tại, tránh tạo bằng chứng giả về antivirus.

## Mở bằng Wireshark

1. Mở pcap, chọn một TCP stream liên quan đúng IP client/proxy/testweb.
2. Với phiên bump, vào Preferences → Protocols → TLS → `(Pre)-Master-Secret log filename`, chọn file `.client.keys` cho chặng client hoặc `.squid.keys` khi đã kiểm chứng phù hợp giao thức upstream. Có thể ghép key log: `cat captures/bump-demo.*.keys > captures/bump-demo.keys`.
3. Chọn Decode As khi Wireshark không tự nhận HTTP trên cổng 3128 hoặc ICAP trên 1344.
4. Chụp ảnh Wireshark thật sau khi chọn packet/display filter; ghi tên file, frame và nhận xét. Tóm tắt tcpdump không phải ảnh Wireshark.

Squid `tls_key_log` hỗ trợ các TLS connection được Squid nhận hoặc thiết lập, gồm cả phiên bump; không chỉ riêng chặng upstream. [Tài liệu Squid](https://www.squid-cache.org/Doc/config/tls_key_log/). Splice không cung cấp khóa của TLS đầu cuối cho Squid.

Trong lần kiểm Squid 6.14/OpenSSL 3 của lab, file key log Squid chỉ có nhãn `CLIENT_RANDOM`/`RSA`; tshark không giải mã được phiên TLS 1.3 đó bằng file này. File key log của curl có các nhãn traffic secret TLS 1.3 và giải mã được GET phía client. Phân biệt định dạng nhãn theo [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html). Tùy chọn `--upstream-tls12` chỉ dùng cho capture chẩn đoán: thêm `options=NO_TLSv1_3` tạm thời vào `tls_outgoing_options`, sau đó phục hồi template/mode. Nó không thay TLS mặc định của lab và không chứng minh logger đã hỗ trợ TLS 1.3.

| Mục tiêu | Display filter | Bằng chứng cần đọc |
|---|---|---|
| CONNECT | `http.request.method == "CONNECT"` | Hostname/cổng, header test ID |
| SNI | `tls.handshake.extensions_server_name` | Tên được gửi trong ClientHello |
| HTTP bị chặn | `http.response.code == 403` | Trang/header lý do chặn, nếu HTTP đọc được |
| Xác thực | `http.response.code == 407` | Proxy authentication required; cần POL-1 |
| ICAP | `icap` hoặc `tcp.port == 1344` | RESPMOD và phản hồi c-icap; cần THR-4 |
| TLS bump upstream | `ip.addr == 172.30.0.50 && tcp.port == 443` | Phiên Squid↔testweb riêng |
| Nội dung sau giải mã | `http` | GET/path chỉ xuất hiện khi có khóa phù hợp |

Capture HTTP thể hiện nội dung rõ. Capture splice thể hiện CONNECT và TLS đầu cuối; proxy không cung cấp được khóa phiên này. Nếu nạp key log của chính client, Wireshark vẫn có thể giải mã nhờ khóa endpoint — điều đó không chứng minh Squid đã đọc nội dung. Capture bump cùng key log cho thấy hai chặng TLS và GET/path. Capture ICAP phải có lưu lượng cổng 1344, không chỉ có một lượt tải PDF.

DoD TLS-6 yêu cầu ít nhất bốn pcap cùng ảnh Wireshark. Kiểm tra trạng thái chạy thật và các phần còn thiếu trong [trung-handoff.md](trung-handoff.md); không suy ra đã có đủ bốn capture từ việc script tồn tại.
