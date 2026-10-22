# Progress: trạng thái hiện tại

> File này được import vào `CLAUDE.md`, nên được nạp ở mọi phiên Claude Code.
> - Giữ toàn file **≤ 100 dòng**.
> - **Ghi đè** trạng thái hiện tại, không viết nhật ký. Lịch sử xem bằng `git log`.
> - Mỗi track chỉ sửa section của mình. Section “Chung” do TV1 cập nhật.

**Milestone hiện tại:** M1 (khung chạy được). Đã kiểm tay xong, còn thiếu test tự động S0 (THR-2).
**Cập nhật lần cuối:** 2026-10-22, Claude (cùng TV1)

## Chung
- Môi trường: TV1 dùng Docker Desktop trên Mac M2 (arm64). Kali/UTM chỉ dùng làm máy demo (plan §3).
- `make init && make up` chạy được. 4 service healthy: squid, testweb, client-staff, client-guest.
- Đã kiểm tay trên arm64 (2026-10-22):
  - staff/guest → proxy → `http://allowed.lab.test/`: 200 kèm `LAB-ORIGIN`;
  - HTTPS CONNECT: 200, issuer = Lab Public Root CA;
  - đi thẳng không qua proxy: curl exit 6/7, client không có default route;
  - `access.log` có các dòng TCP_MISS/200 và TCP_TUNNEL/200.
- Đã chạy test trên: arm64 ✅ (thủ công), amd64 ❌ (chưa)
- Profile chưa bật: `av` (icap, clamav, THR-4), `dashboard` (goaccess), `capture` (sniffer), `p2` (tcpecho).

## Track INF/POL (TV1, arm64)
- Xong: INF-1, INF-2, INF-3 (Squid 6.14 `squid-openssl`, render template, `-k parse` lúc start, healthcheck `squid -k check`).
- `40-access.conf` đang ở dạng khung (cho phép cả 2 LAN), chưa có auth.
- Bước tiếp: POL-1 (auth) → POL-2 (list + ACL) → POL-3 (`http_access` §5.4, trang chặn) → POL-4.
- Blocker: —

## Track TLS (TV2, amd64)
- Xong (Claude làm trước để mở khóa M1): TLS-1 `scripts/gen-certs.sh` (idempotent, `--force`, tương thích LibreSSL). Image client cài CA theo `MANAGED`.
- Việc của TV2:
  - Review TLS-1 trên amd64.
  - TLS-2: `tests/probe/probe.sh` theo hợp đồng JSON spec §9.1. Thư mục mới chỉ có trong mount, chưa có file.
  - TLS-3: SslBump. Tạo `docker/squid/templates/sslbump-{splice,bump,selective}.conf.tmpl`; entrypoint tự dùng template theo `TLS_MODE`, nếu thiếu thì dùng placeholder.
- Blocker: —

## Track THR (TV3, amd64)
- Xong một phần THR-1 (Claude): testweb có `/`, `/upload`, `/dns-query`, `/cacheable/<any>/{1m,2m,10m}.bin`, `/nocache/1m.bin`, TLS 443, đủ alias `*.lab.test`.
- Việc của TV3:
  - Hoàn tất THR-1: `/files/*`, `/dl/*`, `/login`, `/payload.bin` theo spec §8. Có `TODO(THR-1)` trong `docker/testweb/nginx.conf`.
  - THR-3: logformat `lab` trong `conf.d/60-logging.conf` (hiện chỉ có `access.log` dạng squid).
  - THR-2: `tests/run_all.py` + `s00_smoke.py`.
  - THR-4: bỏ profile `av`, viết `docker/icap`. Image ClamAV là `clamav/clamav-debian:1.4`.
- Blocker: —

## Kết quả test gần nhất
| Ngày | Arch | Lệnh | Kết quả |
|---|---|---|---|
| 2026-10-22 | arm64 | `make up`; curl qua proxy (HTTP/HTTPS); curl direct; `squid -k parse/check/reconfigure`; `make lint` | Tất cả đạt (kiểm tay, chưa có runner) |
