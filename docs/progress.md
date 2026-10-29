# Progress: trạng thái hiện tại

> File này được import vào `CLAUDE.md`, nên được nạp ở mọi phiên Claude Code.
> - Giữ toàn file **≤ 100 dòng**.
> - **Ghi đè** trạng thái hiện tại, không viết nhật ký. Lịch sử xem bằng `git log`.
> - Mỗi track chỉ sửa section của mình. Section “Chung” do TV1 cập nhật.

**Milestone hiện tại:** đang hoàn thiện M1 (khung chạy được). Đã kiểm tay, còn thiếu test tự động phần khung; kiểm tra S0 đầy đủ sau khi triển khai antivirus, trước M2.
**Cập nhật lần cuối:** 2026-10-28, Codex (làm rõ phân công/lộ trình trong plan; testweb thuộc TV2; kết quả chạy giữ theo lần kiểm 2026-10-22)

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
- POL-1 (nhánh `pol/POL-1-auth`, chưa commit): `policy/auth/users.lab`; entrypoint sinh `users.htpasswd` (apr1) và `group_{admin,staff}.txt` trong container; `conf.d/12-acl-auth.conf` (`auth_param`, `authenticated`, `grp_admin`, `grp_staff`).
- `40-access.conf` vẫn là khung: guest LAN mở, nguồn khác `deny !authenticated` rồi cho phép `grp_admin`/`grp_staff`. Thứ tự đầy đủ để POL-3 làm.
- Kiểm tay arm64 (2026-10-28): staff anon/badpass/user lạ → 407; alice/bob/admin1 → 200; CONNECT anon → 407, alice → 200; guest anon → 200; host 127.0.0.1 anon → 407. `access.log` ghi đúng username. `squid -k parse` sạch, `make lint` ok.
- Lưu ý cho TLS-2: CONNECT bị 407 thì curl ra `000`/exit 56, probe phải phân loại là `AUTH_REQUIRED`.
- Bước tiếp: POL-2 (list + ACL) → POL-3 (`http_access` §5.4, trang chặn) → POL-4. Cần người amd64 kiểm POL-1.
- Blocker: —

## Track TLS (TV2, amd64)
- Xong (Claude làm trước để mở khóa M1): TLS-1 `scripts/gen-certs.sh` (idempotent, `--force`, tương thích LibreSSL). Image client cài CA theo `MANAGED`.
- Xong một phần TLS-9 (Claude): testweb có `/`, `/upload`, `/dns-query`, `/cacheable/<any>/{1m,2m,10m}.bin`, `/nocache/1m.bin`, TLS 443, đủ alias `*.lab.test`.
- Việc của TV2:
  - Hoàn tất TLS-9 (testweb): `/files/*`, `/dl/*`, `/login`, `/payload.bin` theo spec §8. Có `TODO(TLS-9)` trong `docker/testweb/nginx.conf`.
  - Review TLS-1 trên amd64.
  - TLS-2: `tests/probe/probe.sh` theo hợp đồng JSON spec §9.1. Thư mục mới chỉ có trong mount, chưa có file.
  - TLS-3: SslBump. Tạo `docker/squid/templates/sslbump-{splice,bump,selective}.conf.tmpl`; entrypoint tự dùng template theo `TLS_MODE`, nếu thiếu thì dùng placeholder.
- Blocker: —

## Track THR (TV3, amd64)
- Testweb do TV2 phụ trách (TLS-9); TV3 kiểm tra dữ liệu thử phục vụ antivirus/phishing và viết test THR.
- Việc của TV3:
  - THR-3: logformat `lab` trong `conf.d/60-logging.conf` (hiện chỉ có `access.log` dạng squid).
  - THR-2: `tests/run_all.py` + `s00_smoke.py`.
  - THR-4: bỏ profile `av`, viết `docker/icap`. Image ClamAV là `clamav/clamav-debian:1.4`.
- Blocker: —

## Kết quả test gần nhất
| Ngày | Arch | Lệnh | Kết quả |
|---|---|---|---|
| 2026-10-22 | arm64 | `make up`; curl qua proxy (HTTP/HTTPS); curl direct; `squid -k parse/check/reconfigure`; `make lint` | Tất cả đạt (kiểm tay, chưa có runner) |
