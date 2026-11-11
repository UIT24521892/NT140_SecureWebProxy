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
- `40-access.conf` đang ở dạng khung (cho phép cả 2 LAN), chưa có auth.
- Bước tiếp: POL-1 (auth) → POL-2 (list + ACL) → POL-3 (`http_access` §5.4, trang chặn) → POL-4.
- Blocker: —

## Track TLS (TV2, amd64)
- Cập nhật 2026-11-07, Codex/TV2, amd64. Đã triển khai mã TLS-1/2/3/4/5/6/7/9, DOC-2; TLS-8 chưa làm (P2).
- PKI/probe: 9 test đạt (sinh/giữ/xoay CA, phát hiện key lệch, 6 outcome bằng curl thật); testweb: 5 test đạt, đủ alias/path/MIME/archive.
- Ba mode đổi bằng `scripts/set-tls-mode.sh`, SSL DB/CA được chuẩn bị, parse sạch; staff bump, guest/nobump splice, SNI terminate, pinning/unmanaged đúng.
- S7/S8/S9: 18/25 đạt; 7 FAIL giữ nguyên expect: T7.1/2, T8.2/7, T9.4/6/7 (thiếu POL-3/5). Xem `results/tls/20261107-203319-616b2e/`.
- Case hỗ trợ: T6.7 đạt; T1.5/T6.8 chưa đạt do POL-3. Xem `results/tls/20261107-205119-786d79/`.
- Capture: 4 pcap của 3 loại HTTP/splice/bump (một bump TLS1.2 chẩn đoán); tshark giải mã GET client TLS1.3 và upstream TLS1.2. Chưa có ICAP/ảnh Wireshark.
- Benchmark: 500 request (50/payload), B1/B2/B5/B6/B7 đạt; B3 SKIP (POL-5), B4/B8 SKIP (THR-4). `results/bench/20261107-204741-89a07c/` có CSV/MD/CPU-RAM.
- Kiểm tra: build/up trên amd64, Compose config, ShellCheck, py_compile, test thật; `make test P=P0` chưa chạy được vì THR-2 chưa có runner.
- Bàn giao: `docs/trung-handoff.md`, `tls-limitations.md`, `wireshark.md`. Dùng log TLS + cổng client để nối dòng CONNECT cuối bị mất header test ID.
- Bàn giao 2026-11-09: [x] nhánh riêng; [x] clone sạch amd64 tại `cbc7cb1f7dc75a5837b5838a87bc95f79c605f52`; [x] [PR #3](https://github.com/UIT24521892/NT140_SecureWebProxy/pull/3). ZIP gửi riêng được chốt theo PR-head SHA, có README-evidence/SHA256SUMS/checksum ZIP.
- Clone sạch 09/11: init/build/up + 3 mode parse + restart/probe đạt; PKI/probe 9/9, testweb 5/5; S7–S9 vẫn 18/25, SUPPORT 1/3; benchmark 500 mẫu, B3/B4/B8 vẫn SKIP. Runner phục hồi mode/giờ và giữ nguyên .env; parser THR-3 16 trường đạt. Output: `results/handoff/20261109/`; không suy ra auth đã đạt khi POL-1 chưa ghép.
- Còn chờ: POL-2/3/5 + THR-2/4, chạy arm64, ảnh ICAP/Wireshark, review DOC-2. Lab đã phục hồi selective/giờ ban đầu, tắt TLS key log tạm.

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
| 2026-10-22 | arm64 | `make up`; curl qua proxy (HTTP/HTTPS); curl direct; `squid -k parse/check/reconfigure`; `make lint` | Tất cả đạt (kiểm tay, chưa có runner) |
