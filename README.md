# NT140 – Secure Web Gateway Lab

Đồ án môn NT140 (An toàn mạng, UIT), Đề tài 03: *Nghiên cứu và triển khai Secure Web Proxy/Gateway*.

Lab Docker Compose gồm:
- Squid 6 làm forward proxy, kèm SslBump;
- c-icap + ClamAV quét file tải xuống;
- testweb nginx giả lập Internet trên domain `*.lab.test`;
- 2 client: `client-staff` (managed) và `client-guest` (BYOD);
- bộ test tự động cho các kịch bản S0–S11.

## Tài liệu

| File | Nội dung |
|---|---|
| [spec.md](spec.md) | Đặc tả kỹ thuật (nguồn sự thật) |
| [plan.md](plan.md) | Phân công 3 người, task, lộ trình |
| [CLAUDE.md](CLAUDE.md) | Quy tắc cho Claude Code |
| [docs/progress.md](docs/progress.md) | Trạng thái hiện tại |

## Chạy nhanh

Yêu cầu: Docker + Compose v2 (Docker Desktop trên macOS/Windows, hoặc Docker Engine trên Linux), Python ≥ 3.10.

```bash
make init     # tạo .env, feed rỗng, work_hours.conf, cert
make up       # build và khởi động lab
make ps
make test     # chạy toàn bộ kịch bản (khi đã có test runner)
make help     # danh sách lệnh
```

## Phần TV2 (TLS)

Hướng dẫn chạy, trạng thái nghiệm thu và phụ thuộc: [docs/trung-handoff.md](docs/trung-handoff.md).
Đọc thêm [giới hạn HTTPS](docs/tls-limitations.md) và [capture/Wireshark](docs/wireshark.md).

```bash
make tls-mode MODE=selective
make test-tls S=S8
make capture NAME=demo SECS=30
make bench N=50
```

`test-tls` chạy riêng S7/S8/S9 khi runner toàn dự án của THR-2 chưa có.
Các test policy/cache cần phần TV1, các phép đo ICAP cần THR-4; xem báo cáo thật để biết PASS/FAIL/SKIP.
