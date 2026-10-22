# Verify log

Ghi lại kết quả kiểm chứng các mục **[VERIFY]** trong `spec.md`, và mọi chỗ thực tế khác với spec.
- Chỉ thêm dòng mới, không sửa dòng cũ.
- Nếu có sửa spec thì sửa trong cùng PR.

| Ngày | Người / Arch | Mục spec | Spec giả định | Thực tế (lệnh + bằng chứng) | Quyết định / đã sửa spec? |
|---|---|---|---|---|---|
| 2026-10-22 | Claude / arm64 (Docker Desktop trên Mac M2, tạm thời) | §2.1 `clamav` | `clamav/clamav:1.4` có arm64 | `docker buildx imagetools inspect clamav/clamav:1.4` → chỉ `linux/amd64` (1.5 cũng vậy); `clamav/clamav-debian:1.4` → `linux/amd64` + `linux/arm64` | Dùng `clamav/clamav-debian:1.4`. Đã sửa spec §2.1 |
| 2026-10-22 | Claude / arm64 | §2.1 `squid` | Ubuntu 24.04 có `squid-openssl` | `apt-cache policy squid-openssl` → `6.14-0ubuntu0.24.04.5` | OK, Squid 6.14 |
| 2026-10-22 | Claude / arm64 | §2.1 `icap` | Có `c-icap` + `libc-icap-mod-virus-scan` | `c-icap 1:0.5.10-6.1build2`; `libc-icap-mod-virus-scan 1:0.5.5-2build4.2` (Depends: c-icap, clamav, libclamav12) | OK |
| 2026-10-22 | Claude / arm64 | §1 image base | `ubuntu:24.04`, `nginx:1.27-alpine` multi-arch | Cả hai: `linux/amd64` + `linux/arm64/v8` | OK |
| 2026-10-22 | Claude / arm64 | §1 shellcheck | — | `koalaman/shellcheck:v0.10.0` có amd64 + arm64 | `make lint` chạy shellcheck qua image này nếu máy chưa cài |
| 2026-10-22 | Claude / arm64 | §1 Lab host | Lab VM Ubuntu 24.04 | Giai đoạn đầu phát triển trên Docker Desktop (Mac, bash 3.2) | Script chạy trên host viết tương thích cả bash 3.2/BSD lẫn bash 5/GNU, để chạy được ở cả hai nơi |
| 2026-10-22 | Claude | §5.5 | Entrypoint tự sinh `work_hours.conf` nếu thiếu | `./policy` mount ro (§15) nên entrypoint không ghi được | `make init` sinh file. Entrypoint chỉ kiểm tra và báo lỗi. Đã sửa spec §5.5 |
| 2026-10-22 | Claude / arm64 | §2.1, §6 | `squid-openssl` có SslBump | `squid -v` → `Squid Cache: Version 6.14`, có `--with-openssl --enable-ssl-crtd --enable-icap-client --enable-delay-pools`; có `/usr/lib/squid/{security_file_certgen,basic_ncsa_auth,log_file_daemon}` | OK |
| 2026-10-22 | Claude / arm64 | §15 | `/etc/squid/squid.conf` của gói là bản có comment đầy đủ | 9397 dòng, 387 mục `#  TAG:`. Đã copy sang `/usr/share/doc/nt140/squid.conf.documented` | OK |
| 2026-10-22 | Claude / arm64 | §5.4 | `to_localhost`, `to_linklocal` dựng sẵn | Doc dòng 1387: "ACLs all, manager, localhost, to_localhost, to_linklocal, and CONNECT are predefined." | OK, không tự định nghĩa lại |
| 2026-10-22 | Claude / arm64 | §5.2, §5.4, §6.1 | Có `annotate_transaction`, `note`, `at_step`, `req_header`, `rep_mime_type`, `tls_key_log`, `on_unsupported_protocol` | Đều có trong `squid.conf.documented` (6.14) | OK |
