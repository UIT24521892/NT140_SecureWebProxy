# Progress: trạng thái hiện tại

> File này được import vào `CLAUDE.md`, nên được nạp ở mọi phiên Claude Code.
> - Giữ toàn file **≤ 100 dòng**.
> - **Ghi đè** trạng thái hiện tại, không viết nhật ký. Lịch sử xem bằng `git log`.
> - Mỗi track chỉ sửa section của mình. Section “Chung” do TV1 cập nhật.

**Milestone hiện tại:** đang hoàn thiện M1 (khung chạy được). Đã kiểm tay, còn thiếu test tự động phần khung; kiểm tra S0 đầy đủ sau khi triển khai antivirus, trước M2.
**Cập nhật lần cuối:** 2026-11-09, TV1 (đồng bộ THR-3 từ main, build/up và kiểm lại POL-1 + log thật trên arm64)

## Chung
- Môi trường: TV1 dùng Docker Desktop trên Mac M2 (arm64). Kali/UTM chỉ dùng làm máy demo (plan §3).
- Hướng dẫn chạy lab: `README.md`, mục “Chạy lab từ đầu”. Phần Windows (cách B, D) và Linux (cách C) chưa được ai chạy thử, cần TV2/TV3 xác nhận.
- `make init && make up` chạy được. 4 service chạy: squid, testweb `healthy`; client-staff, client-guest `Up` (không có healthcheck).
- Đã kiểm tay trên arm64 (2026-10-22):
  - staff/guest → proxy → `http://allowed.lab.test/`: 200 kèm `LAB-ORIGIN`;
  - HTTPS CONNECT: 200, issuer = Lab Public Root CA;
  - đi thẳng không qua proxy: curl exit 6/7, client không có default route;
  - `access.log` có các dòng TCP_MISS/200 và TCP_TUNNEL/200.
- Đã chạy test trên: arm64 ✅ (thủ công), amd64 ❌ (chưa)
- THR-3 đã merge vào `main` qua PR #2 (07/11) và ghép vào nhánh POL-1. TV1 kiểm trên arm64 (09/11): parse sạch; parser đọc được log thật 16 trường. Mục THR bên dưới giữ thông tin bàn giao của TV3.
- Profile chưa bật: `av` (icap, clamav, THR-4), `dashboard` (goaccess), `capture` (sniffer), `p2` (tcpecho).

## Track INF/POL (TV1, arm64)
- Xong: INF-1, INF-2, INF-3 (Squid 6.14 `squid-openssl`, render template, `-k parse` lúc start, healthcheck `squid -k check`).
- POL-1 (nhánh `pol/POL-1-auth`, đã commit `62514b4`, chưa merge vào `main`): `policy/auth/users.lab`; entrypoint sinh `users.htpasswd` (apr1) và `group_{admin,staff}.txt` trong container; `conf.d/12-acl-auth.conf` (`auth_param`, `authenticated`, `grp_admin`, `grp_staff`).
- `40-access.conf` vẫn là khung: guest LAN mở, nguồn khác `deny !authenticated` rồi cho phép `grp_admin`/`grp_staff`. Thứ tự đầy đủ để POL-3 làm.
- Kiểm arm64 (2026-11-09): 31/31 kiểm tra độc lập đạt (16 request HTTP/HTTPS, 8 dòng log theo test ID, định dạng log/không lộ mật khẩu, cô lập mạng và origin). Staff anon/badpass/user lạ, host anon → 407; alice/bob/admin1 và guest anon → 200. Bằng chứng: `results/pol1/20261109-arm64/{results.md,results.json,verify.py}` (gitignored).
- `make init`, `docker compose config --quiet`, `make build`, `make up`, `squid -k parse`, `make lint`, `py_compile` và parser `--check` đạt. `make test S=S1`, `S=S2`, `P=P0` đều dừng do chưa có THR-2; 31 kiểm tra trên không thay thế runner chung.
- Lưu ý cho TLS-2: CONNECT bị 407 thì curl ra `000`/exit 56, probe phải phân loại là `AUTH_REQUIRED`.
- Bước tiếp: POL-2 (list + ACL) → POL-3 (`http_access` §5.4, trang chặn) → POL-4. Cần người amd64 kiểm POL-1.
- Checklist chốt POL-1: [x] đồng bộ THR-3 từ `main`; [x] build/up, kiểm auth và log thật trên arm64; [x] lưu hướng dẫn README; [ ] nghiệm thu amd64 + review/merge PR #1.
- Blocker nghiệm thu: thiếu THR-2; cần TV2/TV3 kiểm lại đúng nhánh PR #1 trên amd64 và có người review theo plan §4. Báo cáo amd64 trong handoff TLS chưa xác nhận bản POL-1 đã đồng bộ THR-3 này.

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
  - THR-3 (đang review, nhánh `thr/THR-3-logformat`): logformat `lab` 16 trường TAB → `access_lab.log`; parser `tests/lib/squidlog.py` (`find_by_test_id`, `evidence`, `--check`). Đã kiểm: 16 trường, `py_compile`, parser trên log mẫu. **Chưa** chạy `squid -k parse` / log thật (cần amd64 + arm64). Chưa verify `%adapt::sum_trs`.
  - THR-2: `tests/run_all.py` + `s00_smoke.py`.
  - THR-4: bỏ profile `av`, viết `docker/icap`. Image ClamAV là `clamav/clamav-debian:1.4`.
- Blocker: —

## Kết quả test gần nhất
| Ngày | Arch | Lệnh | Kết quả |
|---|---|---|---|
| 2026-11-09 | arm64 | Init/config/build/up; auth HTTP/HTTPS; log THR-3; cô lập mạng; parse; lint; py_compile | 31/31 kiểm tra độc lập đạt; parser đọc 16 dòng thật, đủ 16 trường. S1/S2/P0 chưa chạy được vì thiếu THR-2 |
| 2026-11-06 | arm64 | Các lệnh Bước 4 của README trên lab đang chạy; `make init`, `make build` trên bản clone sạch; `make lint` | Đạt (kiểm tay). Chưa chạy lại `make down` + `make up` từ đầu |
| 2026-10-22 | arm64 | `make up`; curl qua proxy (HTTP/HTTPS); curl direct; `squid -k parse/check/reconfigure`; `make lint` | Tất cả đạt (kiểm tay, chưa có runner) |
