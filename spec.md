# SPEC: Secure Web Gateway Lab (NT140, Đề tài 03)

> Đây là đặc tả kỹ thuật và là **nguồn sự thật** khi hiện thực. Thứ tự làm việc nằm trong `plan.md`. Nếu `plan.md` và `spec.md` mâu thuẫn thì theo `spec.md`.
>
> Mục đánh dấu **[VERIFY]** là chi tiết có thể khác giữa các phiên bản phần mềm. Phải kiểm tra trên image thực tế. Nếu thực tế khác spec thì làm theo thực tế, ghi lại vào `docs/verify-log.md`, rồi cập nhật spec này.

---

## 0. Bối cảnh và mục tiêu

Đây là đồ án môn NT140 (An toàn mạng, UIT), Đề tài 03: *Nghiên cứu và triển khai Secure Web Proxy/Gateway*. Đề tài nghiên cứu vai trò của SWG trong việc kiểm soát truy cập Web và bảo vệ người dùng trước website độc hại, phishing, malicious download và nội dung không được phép.

Bài làm phải đáp ứng đủ các yêu cầu sau của đề:

| # | Yêu cầu | Mục trong spec |
|---|---|---|
| R1 | Forward proxy dùng Squid | §2, §6 |
| R2 | Chính sách truy cập theo user / network / domain | §4, §5 |
| R3 | URL/domain filtering, caching, logging | §5, §10, §11 |
| R4 | HTTPS/TLS handling và chứng minh giới hạn khi traffic mã hóa | §6, S7, S8, S9 |
| R5 | Quét file tải xuống (ClamAV) | §7, S5 |
| R6 | Có ít nhất 5 security/policy scenario kèm đánh giá định lượng | §13 (S1 → S11) |

**Sản phẩm cần có:**
- Một lab Docker Compose dựng lại được bằng `make init && make up`.
- Bộ kiểm thử tự động sinh bảng kết quả.
- Script đo hiệu năng và phân tích log.
- Tài liệu phục vụ viết báo cáo.

**Non-goals (không làm):**
- Không làm production hay HA.
- **Không** tải hoặc chạy malware thật. Chỉ dùng EICAR.
- **Không** truy cập thật vào bất kỳ URL nào trong threat feed.
- **Không** dùng thương hiệu có thật cho trang phishing mẫu. Chỉ dùng ngân hàng hư cấu “UIT Bank”.

---

## 1. Ràng buộc môi trường

- **Lab host:** bất kỳ máy nào có Docker và Compose v2 (≥ 2.20). Toàn bộ lab nằm trong container, nên phiên bản Squid/c-icap/ClamAV là do image quyết định, không phụ thuộc host. Các host được hỗ trợ:
  - macOS + Docker Desktop. Mac M2 là **arm64**. Đây là môi trường chính của TV1.
  - Máy Linux hoặc Linux VM (Ubuntu 24.04, Debian, Kali…) + Docker Engine, **amd64** hoặc arm64.
  - Windows + Docker Desktop (WSL2 backend). Lệnh chạy trong shell WSL.
  - Cách cài đặt xem `plan.md` §3.
- **Tài nguyên cấp cho Docker:** ≥ 4 vCPU, **≥ 6 GB RAM** (clamd dùng khoảng 1.5–2 GB **[VERIFY]**), ≥ 40 GB disk.
- **Image:**
  - Mọi image phải chạy native trên cả `linux/arm64` và `linux/amd64`. Kiểm tra bằng `docker buildx imagetools inspect <image:tag>`.
  - **Cấm** dùng `platform: linux/amd64` hoặc giả lập QEMU để né lỗi arm64.
  - Pin version cụ thể, **cấm `:latest`**.
- **Script chạy trên host** (Makefile, `scripts/`, `tests/run_all.py`):
  - Phải chạy được trên **cả bash 3.2/BSD (macOS) lẫn bash 5/GNU (Linux)**. Không dùng `mapfile`, associative array, `sed -i`, `grep -P`, `readlink -f`.
  - Logic phức tạp (test runner, phân tích log, feed) viết bằng **Python ≥ 3.10, chỉ dùng stdlib**, không cài thêm gói pip.
- **Script chạy trong container (Ubuntu 24.04 / Alpine):** dùng bash 5 hoặc POSIX sh tùy image.
- Mọi script bash phải có `set -euo pipefail` và qua được `shellcheck` (`make lint` chạy shellcheck bằng image `koalaman/shellcheck:v0.10.0`).
- **Kali Linux (tùy chọn):** dùng làm máy client/phân tích khi demo (Wireshark, trình duyệt, công cụ thử bypass). Kali không phải nền chuẩn để chạy test, vì là bản rolling nên khó tái lập.
- Múi giờ: `TZ=Asia/Ho_Chi_Minh` cho mọi container.
- **Không commit:** private key, htpasswd, feed đã tải, log, pcap, kết quả thô. Danh sách cụ thể ở §15.

---

## 2. Kiến trúc

### 2.1 Services (`docker-compose.yml`)

| Service | Image / base | Vai trò | Networks | Ưu tiên |
|---|---|---|---|---|
| `squid` | build `docker/squid` từ `ubuntu:24.04`, gói **`squid-openssl`** (gói `squid` thường không có SslBump) | Forward proxy, ACL, SslBump, ICAP client, cache, log | lan_staff, lan_guest, svc, wan | P0 |
| `icap` | build `docker/icap` từ `ubuntu:24.04`, gói `c-icap` + `libc-icap-mod-virus-scan` **[VERIFY]** | ICAP server, chuyển nội dung sang clamd | svc | P0 |
| `clamav` | `clamav/clamav-debian:1.4` (đã kiểm: có amd64 + arm64; bản `clamav/clamav` Alpine chỉ có amd64). Dự phòng: tự build từ `ubuntu:24.04` với `clamav-daemon` + `clamav-freshclam` | clamd + freshclam | svc, wan | P0 |
| `testweb` | build `docker/testweb` từ `nginx:1.27-alpine` | Giả lập “Internet”: site sạch, mạng xã hội, phishing giả, file EICAR, nội dung cache | wan | P0 |
| `client-staff` | build `docker/client` từ `ubuntu:24.04` | Máy nhân viên (managed, tin Proxy CA) | lan_staff | P0 |
| `client-guest` | cùng image | Máy khách/BYOD (unmanaged, **không** tin Proxy CA) | lan_guest | P0 |
| `goaccess` | `allinurl/goaccess` (pin version) **[VERIFY]** | Dashboard HTML từ `access.log` | wan | P1 |
| `sniffer` | `nicolaka/netshoot` (pin version), `network_mode: service:squid`, compose profile `capture` | tcpdump | — | P1 |
| `tcpecho` | `alpine/socat` (pin), nghe TCP 443 rồi echo lại | Thử tunnel không phải TLS qua CONNECT | wan | P2 |

### 2.2 Networks

| Network | Subnet | `internal` | IP cố định |
|---|---|---|---|
| `lan_staff` | 10.10.0.0/24 | **true** | squid 10.10.0.10, client-staff 10.10.0.101 |
| `lan_guest` | 10.20.0.0/24 | **true** | squid 10.20.0.10, client-guest 10.20.0.101 |
| `svc` | 10.30.0.0/24 | **true** | squid 10.30.0.10, icap 10.30.0.20, clamav 10.30.0.21 |
| `wan` | 172.30.0.0/24 | false | squid 172.30.0.10, clamav 172.30.0.21, testweb 172.30.0.50, goaccess 172.30.0.60 |

- `internal: true` làm client không có default route ra ngoài, nên con đường duy nhất là đi qua squid. Đây là cơ chế **egress enforcement** của lab, tương đương việc firewall chặn kết nối 80/443 trực tiếp. Báo cáo phải nêu rõ điểm này.
- Port publish chỉ bind `127.0.0.1` **của Lab VM**:
  - `squid` 3128: để demo bằng trình duyệt.
  - `goaccess` 7890.
  - Truy cập từ laptop qua SSH tunnel: `ssh -L 3128:127.0.0.1:3128 -L 7890:127.0.0.1:7890 labvm`.

### 2.3 Domain giả lập (TLD `.lab.test`, theo RFC 6761)

Tất cả hostname dưới đây là **network alias của `testweb` trên mạng `wan`**, để squid phân giải được qua Docker DNS. Chúng dùng chung một cert wildcard.

| Hostname | Vai trò | Thuộc list |
|---|---|---|
| `allowed.lab.test` | Site sạch, có `/upload` | — |
| `social.lab.test` | Mạng xã hội | `cat_social` |
| `games.lab.test` | Game | `cat_games` |
| `stream.lab.test` | Streaming | `cat_streaming` |
| `gamble.lab.test` | Cờ bạc | `cat_gambling` |
| `uitbank.lab.test` | Site **thật** của ngân hàng hư cấu UIT Bank | `nobump_sni` |
| `uitbank-secure-login.lab.test` | Phishing giả mạo UIT Bank, **đã có** trong blocklist | `threat_phishing` |
| `uitbank-verify-account.lab.test` | Phishing “zero-day”, **chưa có** trong blocklist | — |
| `malware-cdn.lab.test` | Domain phát tán malware | `threat_malware` |
| `downloads.lab.test` | Site tải file (EICAR, file thử) | — |
| `cache.lab.test` | Nội dung cacheable | — |
| `pinned.lab.test` | “App” có pin public key | — |
| `dns.lab.test` | DoH resolver giả | `doh_providers` |

### 2.4 Luồng xử lý một request

```
client ──(GET http://… | CONNECT host:443)──▶ squid
  1. http_access (ACL network/user/domain/time/ext)  → deny ⇒ trang ERR_LAB_*
  2. [HTTPS] ssl_bump: peek step1 → terminate (threat SNI) | splice | bump
  3. [bumped] http_access chạy lại trên request bên trong (thấy path, header)
  4. forward → origin (testweb / Internet)
  5. response → ICAP RESPMOD (c-icap → clamd)          → virus ⇒ trang VIRUS_FOUND
  6. http_reply_access (MIME type)                      → deny ⇒ ERR_LAB_FILETYPE_MIME
  7. cache store (nếu cacheable) → client
  8. ghi access.log + access_lab.log
```

`docs/architecture.md` phải vẽ lại luồng này bằng sơ đồ Mermaid.

---

## 3. PKI (`scripts/gen-certs.sh`)

Script sinh các file sau vào thư mục `certs/`. Script phải idempotent: không ghi đè file đã có, trừ khi chạy với `--force`.

| File | Subject / thuộc tính | Ai tin |
|---|---|---|
| `lab-public-ca.crt/.key` | `CN=NT140 Lab Public Root CA, O=UIT NT140 Lab`, CA:TRUE | Mọi client và squid (giả lập Web PKI công khai) |
| `testweb.crt/.key` | Ký bởi lab-public-ca, SAN `*.lab.test`, `lab.test`, hạn ≤ 825 ngày, EKU serverAuth | — |
| `lab-proxy-ca.crt/.key` | `CN=NT140 SWG Proxy CA, O=UIT NT140 Lab`, CA:TRUE, keyUsage `keyCertSign,cRLSign` | **Chỉ** client managed (`client-staff`) |
| `pinned.sha256` | `sha256//<base64 SPKI hash>` của key testweb, dùng cho `curl --pinnedpubkey` | — |

Cách các thành phần dùng các file này:
- **squid image:** thêm `lab-public-ca.crt` vào system trust (`update-ca-certificates`). Nhờ vậy, khi bump, Squid verify được testweb mà vẫn verify được Internet thật.
- **entrypoint của squid:** copy `lab-proxy-ca.*` vào `/etc/squid/ssl/`, chủ sở hữu `root:proxy`, quyền key `0640`.
- **entrypoint của client:** luôn cài `lab-public-ca.crt`. Chỉ cài thêm `lab-proxy-ca.crt` khi `MANAGED=1`.

---

## 4. Người dùng và nhóm

- **Xác thực:** dùng `basic_ncsa_auth`.
  - Nguồn dữ liệu là file `policy/auth/users.lab` (commit được vì chỉ dùng cho lab), định dạng `user:password:group`.
  - Entrypoint của squid sinh `/etc/squid/auth/users.htpasswd` từ file này **bên trong container** bằng `htpasswd` (gói `apache2-utils`). Host không cần cài công cụ nào.
- **Tài khoản lab:**

  | user | password | group |
  |---|---|---|
  | alice | alice123 | staff |
  | bob | bob123 | staff |
  | admin1 | admin123 | admin |

- **Nhóm:** entrypoint sinh `/etc/squid/auth/group_admin.txt` và `group_staff.txt` từ cột group, rồi dùng: `acl grp_admin proxy_auth "/etc/squid/auth/group_admin.txt"`.
- **Tham số auth:** `auth_param basic realm NT140 Secure Web Gateway`, `credentialsttl 1 hour`, `children 5`.
- **P2:** chuyển sang OpenLDAP với `basic_ldap_auth` và `ext_ldap_group_acl`, **giữ nguyên tên ACL** `grp_admin`/`grp_staff` để không phải sửa policy.

---

## 5. Chính sách (policy)

### 5.1 Danh sách ACL (`policy/lists/`)

**Định dạng `dstdomain` / `ssl::server_name`:**
- `.example.com` khớp với domain và mọi subdomain.
- `host.example.com` chỉ khớp đúng host đó.

**Seed cục bộ** (commit, thư mục `policy/lists/local/`):

| File | Nội dung tối thiểu |
|---|---|
| `social.txt` | `.social.lab.test`, `.facebook.com`, `.instagram.com`, `.tiktok.com`, `.x.com` |
| `games.txt` | `.games.lab.test`, `.roblox.com`, `.steampowered.com` |
| `streaming.txt` | `.stream.lab.test`, `.youtube.com`, `.googlevideo.com`, `.netflix.com` |
| `gambling.txt` | `.gamble.lab.test` |
| `phishing.txt` | `uitbank-secure-login.lab.test` |
| `malware.txt` | `.malware-cdn.lab.test` |
| `doh.txt` | `dns.lab.test`, `.cloudflare-dns.com`, `dns.google`, `.dns.quad9.net`, `doh.opendns.com`, `.dns.nextdns.io` |
| `nobump.txt` | `.uitbank.lab.test` và vài ngân hàng/y tế thật (vd `.vietcombank.com.vn`) |
| `blocked_paths.txt` | regex: `^https?://allowed\.lab\.test/upload` |
| `never_block.txt` | Allowlist dùng khi chuẩn hóa feed (§12), vd `.google.com`, `.github.com`, `.microsoft.com` |

**Feed tự sinh** (gitignored, thư mục `policy/lists/feeds/`):
- Các file: `phishing.txt`, `malware.txt`, `threat_ips.txt`, `ut1_<category>.txt`.
- Lệnh `make init` phải tạo sẵn các file này ở dạng **rỗng**. Squid sẽ fatal nếu file ACL không tồn tại.

### 5.2 Định nghĩa ACL

Tên ACL là **cố định**. Test và tài liệu đều dựa vào các tên này.

| ACL | Kiểu | Giá trị / nguồn |
|---|---|---|
| `net_staff` | `src` | 10.10.0.0/24 |
| `net_guest` | `src` | 10.20.0.0/24 |
| `authenticated` | `proxy_auth` | `REQUIRED` |
| `grp_admin`, `grp_staff` | `proxy_auth` | file nhóm (§4) |
| `work_hours` | (xem §5.5) | `include /etc/squid/policy/generated/work_hours.conf` |
| `cat_social` | `dstdomain` | `local/social.txt` + `feeds/ut1_social_networks.txt` |
| `cat_games` | `dstdomain` | `local/games.txt` + `feeds/ut1_games.txt` |
| `cat_streaming` | `dstdomain` | `local/streaming.txt` |
| `cat_gambling` | `dstdomain` | `local/gambling.txt` + `feeds/ut1_gambling.txt` |
| `threat_phishing` | `dstdomain` | `local/phishing.txt` + `feeds/phishing.txt` + `feeds/ut1_phishing.txt` |
| `threat_malware` | `dstdomain` | `local/malware.txt` + `feeds/malware.txt` + `feeds/ut1_malware.txt` |
| `threat_ips` | `dst` | `feeds/threat_ips.txt` |
| `threat_sni` | `ssl::server_name` | cùng các file của `threat_phishing` và `threat_malware` |
| `nobump_sni` | `ssl::server_name` | `local/nobump.txt` |
| `doh_providers` | `dstdomain` | `local/doh.txt` |
| `dst_is_ip` | `dstdom_regex -n` | `^[0-9]+(\.[0-9]+){3}$` và `^\[?[0-9a-fA-F]*:[0-9a-fA-F:.]*\]?$` |
| `blocked_ext` | `urlpath_regex -i` | `\.(exe\|msi\|scr\|bat\|cmd\|ps1\|vbs\|jar\|apk\|dmg)(\?.*)?$` |
| `blocked_mime` | `rep_mime_type -i` | `^application/x-msdownload$`, `^application/x-msdos-program$`, `^application/x-dosexec$`, `^application/vnd\.android\.package-archive$` |
| `blocked_paths` | `url_regex -i` | `local/blocked_paths.txt` |
| `step1`/`step2`/`step3` | `at_step` | SslBump1/2/3 |
| `dryrun` | `req_header` | `X-Lab-Dryrun -i ^1$` (§12.3) |
| `mark_<reason>` | `annotate_transaction` | `policy=<reason>` (§5.6) |

### 5.3 Ma trận chính sách (hành vi mong đợi)

Có ba đối tượng:
- **Guest:** nguồn từ `net_guest`, không auth.
- **Staff:** alice/bob, xác thực từ `net_staff`.
- **Admin:** admin1.

Mọi nguồn **không** thuộc `net_guest`, kể cả host truy cập qua `127.0.0.1:3128`, đều phải xác thực và được xử lý theo nhóm như Staff/Admin.

| Đích / hành vi | Guest | Staff | Admin | reason |
|---|---|---|---|---|
| `threat_phishing` | BLOCK | BLOCK | BLOCK | `phishing` |
| `threat_malware`, `threat_ips` | BLOCK | BLOCK | BLOCK | `malware` |
| `doh_providers` | BLOCK | BLOCK | BLOCK | `doh` |
| `dst_is_ip` (truy cập bằng IP) | BLOCK | BLOCK | ALLOW | `ip-literal` |
| `cat_gambling` | BLOCK | BLOCK | ALLOW | `gambling` |
| `cat_social` / `cat_games` / `cat_streaming` | BLOCK | BLOCK nếu `work_hours`, ngoài giờ thì ALLOW | ALLOW | guest: `social`/`games`/`streaming`; staff: `worktime` |
| `blocked_paths` | BLOCK | BLOCK | ALLOW | `path` |
| `blocked_ext` (theo URL) | BLOCK | BLOCK | ALLOW | `filetype` |
| `blocked_mime` (theo response) | BLOCK | BLOCK | ALLOW | `filetype-mime` |
| Phát hiện virus (ICAP) | BLOCK* | BLOCK* | BLOCK* | `malware-content` |
| SNI thuộc `threat_sni` | TERMINATE | TERMINATE | TERMINATE | `sni-threat` |
| Không có hoặc sai credential (ngoài `net_guest`) | — | 407 | 407 | — |
| Còn lại | ALLOW, giới hạn băng thông | ALLOW | ALLOW | — |

\* HTTP thì luôn được quét. HTTPS chỉ được quét khi bị bump (§6.3).

### 5.4 Thứ tự `http_access`

Phải giữ đúng thứ tự dưới đây, vì Squid dùng first match.

```squid
# 0. Chuẩn Squid
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access deny to_localhost                      # [VERIFY] ACL dựng sẵn trong Squid 6
http_access deny to_linklocal
# 1. Threat: áp cho mọi đối tượng
http_access deny threat_phishing mark_phishing
http_access deny threat_malware mark_malware
http_access deny dst_is_ip threat_ips mark_malware # chỉ tra 'dst' khi đích là IP, tránh DNS lookup thừa
http_access deny doh_providers mark_doh
# 2. Guest network (không auth)
http_access deny net_guest dst_is_ip mark_ip_literal
http_access deny net_guest cat_gambling mark_gambling
http_access deny net_guest cat_social mark_social
http_access deny net_guest cat_games mark_games
http_access deny net_guest cat_streaming mark_streaming
http_access deny net_guest blocked_paths mark_path
http_access deny net_guest blocked_ext mark_filetype
http_access allow net_guest
# 3. Các nguồn khác: bắt buộc xác thực
http_access deny !authenticated                    # → 407
http_access allow grp_admin mark_group_admin
http_access deny dst_is_ip mark_ip_literal
http_access deny cat_gambling mark_gambling
http_access deny work_hours cat_social mark_worktime
http_access deny work_hours cat_games mark_worktime
http_access deny work_hours cat_streaming mark_worktime
http_access deny blocked_paths mark_path
http_access deny blocked_ext mark_filetype
http_access allow grp_staff
http_access deny all
```

`http_reply_access`:

```squid
http_reply_access deny net_guest blocked_mime mark_filetype_mime
http_reply_access allow is_admin_note              # acl is_admin_note note policy group-admin
http_reply_access deny blocked_mime mark_filetype_mime
http_reply_access allow all
```

- `mark_group_admin` là ACL kiểu `annotate_transaction policy=group-admin`. Ở bước reply, dùng ACL kiểu `note` để nhận ra admin thay vì gọi lại `proxy_auth` **[VERIFY]**.
- Nếu `note` không hoạt động như mong đợi, có thể dùng `proxy_auth` trong reply access. Ghi lại lựa chọn vào verify-log.
- Lưu ý: annotate `group-admin` sẽ ghi đè key `policy` trong log của request admin được ALLOW. Đây là hành vi chấp nhận được.

### 5.5 Chế độ giờ làm việc

Script `scripts/set-worktime.sh real|always|never` ghi file `policy/generated/work_hours.conf`, sau đó chạy `squid -k reconfigure`.

| Mode | Nội dung | Dùng khi |
|---|---|---|
| `real` | `acl work_hours time MTWHF 08:00-17:00` | Vận hành và demo (mặc định trong `.env`) |
| `always` | `acl work_hours time 00:00-23:59` | Test chặn trong giờ làm |
| `never` | `acl work_hours src 192.0.2.254/32` (TEST-NET-1, không bao giờ khớp) | Test ngoài giờ (mặc định của test runner) |

`make init` sinh file này nếu chưa có, theo `WORK_HOURS_MODE` trong `.env`. Vì `./policy` được mount read-only, entrypoint không ghi được file này. Nếu thiếu file, entrypoint báo lỗi và nhắc chạy `make init`.

### 5.6 Trang chặn và annotate

- **Annotate:** mỗi dòng `deny` kết thúc bằng một ACL `mark_<reason>` (kiểu `annotate_transaction policy=<reason>`). Có hai lý do:
  - log ghi được lý do (`%{policy}note`);
  - `deny_info` gắn vào **ACL cuối cùng** của dòng deny, nên cũng gắn đúng vào `mark_<reason>`.
- **Danh sách reason:** `phishing`, `malware`, `doh`, `ip-literal`, `gambling`, `social`, `games`, `streaming`, `worktime`, `path`, `filetype`, `filetype-mime`, `malware-content`, `sni-threat`. Lỗi mặc định của Squid được tính là `default`.
- **Template trang chặn:**
  - Tên là `ERR_LAB_<REASON>`, viết hoa, đổi `-` thành `_`. Ví dụ: `ERR_LAB_IP_LITERAL`.
  - Nội dung HTML song ngữ Việt/Anh, gồm: lý do, URL (`%U`), IP client (`%i`), user (`%a`), thời gian (`%T`), và marker **bắt buộc** `<!-- LAB-BLOCK reason=<reason> -->`.
- **Cài template:** Dockerfile đặt các template vào error directory của Squid **[VERIFY đường dẫn]**. Nếu dùng `error_directory` riêng thì phải copy kèm toàn bộ template mặc định.
- **Hạn chế cần đưa vào báo cáo:** ở chế độ splice, HTTPS bị chặn ngay tại bước CONNECT, nên trình duyệt **không hiển thị** được trang chặn mà chỉ báo lỗi proxy.

### 5.7 Giới hạn băng thông

```squid
delay_pools 1
delay_class 1 2
delay_parameters 1 -1/-1 ${GUEST_RATE_BYTES}/${GUEST_RATE_BYTES}   # mặc định 262144 (256 KB/s mỗi host)
delay_access 1 allow net_guest
delay_access 1 deny all
```

### 5.8 Cache

- `cache_mem 256 MB`, `maximum_object_size_in_memory 8 MB`.
- `cache_dir ufs /var/spool/squid 2048 16 256`, dùng named volume `squid-cache`.
- `maximum_object_size 64 MB`.
- Giữ `refresh_pattern` mặc định của Ubuntu và không override `Cache-Control` của origin.
  - Lưu ý: dòng mặc định `(/cgi-bin/|\?) 0 0% 0` làm URL có query string không được cache. Vì vậy, khi test cần cache lạnh thì dùng **path duy nhất** (§8), không dùng query.
- HTTPS chỉ cache được khi bị bump.

---

## 6. TLS / SslBump

### 6.1 Port và helper

```squid
http_port 3128 ssl-bump tls-cert=/etc/squid/ssl/lab-proxy-ca.crt tls-key=/etc/squid/ssl/lab-proxy-ca.key \
  generate-host-certificates=on dynamic_cert_mem_cache_size=16MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 16MB
sslcrtd_children 5
sslproxy_cert_error deny all
on_unsupported_protocol respond all      # chặn tunnel không phải TLS khi đang peek/bump
```

- Dòng `http_port` nằm trong file render `conf.d/20-sslbump.conf` (thuộc track TLS).
  - Ở Phase 1, file này chỉ chứa `http_port 3128` thường (placeholder).
  - Phase 3 thay bằng bản ssl-bump ở trên.
- Entrypoint khởi tạo `ssl_db` nếu chưa có (`security_file_certgen -c ...`), sau đó `chown proxy`.
- **P1:** `tls_key_log /var/log/squid/tls_keys.log`, để Wireshark giải mã được chặng squid→origin **[VERIFY có trong Squid 6]**.
- **P2:** transparent mode với `http_port 3129 intercept` và `https_port 3130 intercept ssl-bump ...` (§14).

### 6.2 `TLS_MODE`

Đổi mode bằng `scripts/set-tls-mode.sh <mode>`. Script render `conf.d/20-sslbump.conf` từ template rồi chạy `squid -k reconfigure`.

Phần chung cho mọi mode:

```squid
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3
ssl_bump peek step1
ssl_bump terminate threat_sni mark_sni_threat     # [VERIFY] annotate trong ssl_bump
```

| Mode | Các rule tiếp theo | Ý nghĩa |
|---|---|---|
| `splice` | `ssl_bump splice all` | Không giải mã. Proxy chỉ thấy CONNECT host:port và SNI |
| `bump` | `ssl_bump bump all` | Giải mã tất cả, kể cả guest. Guest sẽ lỗi cert vì không tin Proxy CA |
| `selective` (**mặc định**) | `ssl_bump splice nobump_sni`<br>`ssl_bump splice net_guest`<br>`ssl_bump bump all` | Bump máy managed. Splice với BYOD và nhóm site nhạy cảm (ngân hàng, y tế) |

### 6.3 Hành vi mong đợi theo mode

| Quan sát | splice | selective, Staff | selective, Guest | bump, Guest |
|---|---|---|---|---|
| Issuer của cert mà client thấy | Lab Public Root CA | **SWG Proxy CA** | Lab Public Root CA | SWG Proxy CA → `TLS_ERROR` |
| Proxy thấy URL path của HTTPS | Không | Có | Không | Có |
| Chặn theo path / ext / MIME trên HTTPS | Không | Có | Không | Có |
| ICAP quét file HTTPS | Không | Có | Không | Có |
| Cache HTTPS | Không | Có | Không | Có |
| `curl --pinnedpubkey` tới `pinned.lab.test` | OK | **FAIL** | OK | FAIL |
| `uitbank.lab.test` (nobump) | splice | splice | splice | bump |
| `%ssl::bump_mode` trong log | `splice` | `bump` | `splice` | `bump` |

---

## 7. Quét malware (ICAP + ClamAV)

**Phía Squid** (template, entrypoint render bằng `envsubst`):

```squid
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_header X-Authenticated-User
icap_service svc_av respmod_precache icap://icap:1344/virus_scan bypass=${ICAP_BYPASS_FLAG}
adaptation_access svc_av allow all
```

- `ICAP_BYPASS=off` (mặc định, fail-closed) render thành `bypass=0`. `ICAP_BYPASS=on` (fail-open) render thành `bypass=1`.

**c-icap:**
- Nghe cổng 1344, service `virus_scan`, engine `clamd` (module `clamd_mod`).
- Kết nối tới clamd qua TCP `clamav:3310` **[VERIFY: clamd_mod có hỗ trợ `ClamdHost`/`ClamdPort` không]**. Nếu không hỗ trợ, chia sẻ unix socket qua named volume.
- Đặt `virus_scan.MaxObjectSize 10M` **[VERIFY tên directive]**. File lớn hơn 10 MB sẽ **không được quét**. Đây là hạn chế được kiểm chứng ở T5.5.
- Quét mọi loại file: `virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE DOCUMENT`.
- Template `VIRUS_FOUND` tùy biến: hiển thị tên virus và chứa marker `<!-- LAB-BLOCK reason=malware-content -->`.

**clamav:**
- freshclam chạy khi container start.
- Healthcheck bằng ping clamd **[VERIFY lệnh]**, đặt `start_period` ≥ 300s vì lần đầu tải signature khá lâu.
- Thứ tự phụ thuộc: `squid` depends_on `icap` (healthy), `icap` depends_on `clamav` (healthy).
- Giữ `AlertEncrypted no` (mặc định), nên zip có mật khẩu sẽ lọt qua (T5.4). **P2:** bật `AlertEncrypted yes` rồi đo lại.

**Lưu ý khi test fail-closed/fail-open:**
- Sau khi dừng rồi bật lại `icap`, Squid có thể vẫn coi service là down trong `icap_service_revival_delay`.
- Vì vậy runner phải chạy T5.12/T5.13 **cuối cùng** trong S5, chờ icap healthy, rồi chạy `squid -k reconfigure` để reset trạng thái.

---

## 8. testweb (giả lập Internet)

nginx nghe cổng 80 và 443 (cert `testweb`), `server_name *.lab.test`. Default server cũng trả về trang OK, phục vụ test truy cập bằng IP literal.

**Path và nội dung:**

| Path | Host | Nội dung | Content-Type / header |
|---|---|---|---|
| `/` | mọi host | HTML “OK <host>” + `<!-- LAB-ORIGIN host=$host -->` | text/html |
| `/upload` | allowed | form HTML đơn giản | text/html |
| `/login` | uitbank-secure-login, uitbank-verify-account | trang login giả mạo **UIT Bank** (hư cấu), `action="#"`, không thu thập dữ liệu | text/html |
| `/payload.bin` | malware-cdn | bytes ngẫu nhiên vô hại | application/octet-stream |
| `/files/clean.pdf` | downloads | PDF hợp lệ nhỏ | application/pdf |
| `/files/eicar.com` | downloads | EICAR 68 byte | application/octet-stream |
| `/files/eicar.zip` | downloads | zip chứa eicar.com | application/zip |
| `/files/eicar-nested.zip` | downloads | zip chứa eicar.zip | application/zip |
| `/files/eicar-encrypted.zip` | downloads | zip mật khẩu `infected` | application/zip |
| `/files/eicar-big.zip` | downloads | eicar.com + 12 MB random (store, không nén), tổng > 10 MB | application/zip |
| `/files/setup.exe`, `/files/invoice.pdf.exe` | downloads | PE giả vô hại (bắt đầu bằng `MZ`) | **application/x-msdownload** (phải khai báo `types{}` riêng vì `mime.types` mặc định của nginx map exe thành octet-stream) |
| `/files/renamed-exe.txt` | downloads | PE giả | text/plain |
| `/dl/a1b2c3` | downloads | PE giả, URL không có đuôi | application/x-msdownload + `Content-Disposition: attachment; filename="update.exe"` |
| `/files/app.apk` | downloads | zip giả | application/vnd.android.package-archive |
| `/cacheable/<any>/<size>.bin`, size ∈ {1m, 2m, 10m} | cache | random cố định, mọi `<any>` trả cùng một file | `Cache-Control: public, max-age=3600`, có ETag và Last-Modified |
| `/nocache/1m.bin` | cache | random | `Cache-Control: no-store` |
| `/dns-query` | dns | JSON DoH giả | application/dns-json |

- **Mọi file test được sinh khi container start** (entrypoint, dùng `zip` của apk). Không commit file nhị phân.
- Chuỗi EICAR được **ghép từ nhiều mảnh** trong script, để repo không chứa nguyên chuỗi và AV trên máy dev không báo nhầm. Kiểm tra: `git grep` chuỗi EICAR đầy đủ phải không ra kết quả.

---

## 9. Clients

- **Image:** `ubuntu:24.04`, cài `curl`, `openssl`, `ca-certificates`, `python3`, `dnsutils`, `iproute2`, `iputils-ping`, `netcat-openbsd`.
- **Biến môi trường:**
  - `PROXY_URL`: `http://10.10.0.10:3128` cho staff, `http://10.20.0.10:3128` cho guest.
  - `MANAGED`: 1 cho staff, 0 cho guest.
  - Export thêm `http_proxy`/`https_proxy` để tiện demo bằng tay.
- **Mount:**
  - `./tests/probe` → `/opt/lab` (read-only)
  - `./certs/*.crt` → `/opt/certs`
  - `./captures` → `/captures`, phục vụ `SSLKEYLOGFILE`
- **Command:** `sleep infinity`.

### 9.1 Probe (`tests/probe/probe.sh`, chạy trong client)

```
probe.sh [-u user:pass] [-t TEST_ID] [--cacert FILE] [--pinned] [--dryrun] [--direct] [--max-time N] URL
```

- Luôn gửi `X-Lab-Test-Id` qua cả `-H` lẫn `--proxy-header`, để log liên kết được với test ngay cả với CONNECT.
- Tùy chọn:
  - `--dryrun`: thêm `-H "X-Lab-Dryrun: 1"`.
  - `--direct`: dùng `--noproxy '*'`.
  - `--pinned`: dùng `--pinnedpubkey "$(cat /opt/certs/pinned.sha256)"`.
- Chạy curl với `-v` để đọc header phản hồi CONNECT (`X-Squid-Error`) và issuer của cert.
- **Output:** đúng **1 dòng JSON** ra stdout:

```json
{"test_id":"T1.2","url":"http://social.lab.test/","outcome":"BLOCK","reason":"social",
 "http_code":403,"connect_code":0,"curl_exit":0,"squid_error":"ERR_LAB_SOCIAL",
 "issuer":null,"time_total":0.012,"size":1234,"speed":0}
```

**Phân loại `outcome`** (xét theo thứ tự):
1. `http_code` hoặc `connect_code` = 407 → `AUTH_REQUIRED`.
2. 403 → `BLOCK`. `reason` lấy từ marker `LAB-BLOCK reason=` trong body, hoặc từ header `X-Squid-Error: ERR_LAB_<X>`. Nếu không có thì `reason="default"`.
3. curl exit 35, 51, 58, 60 hoặc 90 (lỗi TLS / verify / pin) → `TLS_ERROR`.
4. curl exit 6, 7 hoặc 28 khi không có phản hồi từ proxy → `CONN_FAIL`.
5. Status 5xx → `UPSTREAM_ERROR`. Bao gồm cả ICAP fail-closed và dryrun.
6. Status 2xx → `ALLOW`.

---

## 10. Logging và observability

### 10.1 Log của Squid (bind mount `./logs/squid` → `/var/log/squid`)

- `access.log`: logformat `squid` gốc, dùng cho GoAccess.
- `access_lab.log`: logformat `lab`, **phân tách bằng TAB**, gồm các trường theo thứ tự:

| # | Trường | Code |
|---|---|---|
| 1 | timestamp | `%{%Y-%m-%dT%H:%M:%S}tl.%03tu` |
| 2 | duration ms | `%tr` |
| 3 | client IP | `%>a` |
| 4 | user | `%un` |
| 5 | result code | `%Ss` (TCP_MISS, TCP_HIT, TCP_MEM_HIT, TCP_DENIED, TCP_TUNNEL…) |
| 6 | HTTP status | `%>Hs` |
| 7 | bytes gửi cho client | `%<st` |
| 8 | method | `%rm` |
| 9 | URL | `%ru` |
| 10 | SNI | `%ssl::>sni` |
| 11 | bump mode | `%ssl::bump_mode` |
| 12 | policy | `%{policy}note` |
| 13 | MIME | `%mt` |
| 14 | tóm tắt adaptation/ICAP | `%adapt::sum_trs` **[VERIFY]** |
| 15 | test id | `%{X-Lab-Test-Id}>h` |
| 16 | hierarchy | `%Sh` |

- `cache.log`: `debug_options ALL,1`.
- Không ghi mật khẩu hay header `Proxy-Authorization` vào log.

### 10.2 Phân tích (`scripts/log_summary.py`)

Đọc `access_lab.log`, sinh `results/log_summary.md` và `log_summary.json`, gồm:
- tổng số request; ALLOW/DENY theo `policy`, theo user, theo IP;
- top 10 domain bị chặn;
- cache hit ratio theo số request và theo bytes (HIT = `%Ss` chứa `HIT`);
- số lượng splice và bump;
- số lần ICAP phát hiện virus.

### 10.3 Dashboard (P1)

Service `goaccess` đọc `access.log` (`--log-format=SQUID`), xuất HTML real-time tại `http://127.0.0.1:7890`.

### 10.4 Capture (P1)

`scripts/capture.sh <name> [seconds]` làm các việc sau:
- Chạy service `sniffer` (profile `capture`) với `tcpdump -i any -w /captures/<name>.pcap`.
- Probe được chạy kèm `SSLKEYLOGFILE=/captures/<name>.keys` để giải mã chặng client→squid.

`docs/wireshark.md` liệt kê các display filter cần dùng:
- `http.request.method == "CONNECT"`
- `tls.handshake.extensions_server_name`
- `icap`
- `http.response.code == 403`
- `http.response.code == 407`

---

## 11. Test runner (`tests/run_all.py`, chạy trong Lab VM)

```
python3 tests/run_all.py [--scenario S5] [--priority P0|P1|all] [--list]
```

- **Định nghĩa scenario:** mỗi scenario là một module `tests/scenarios/sNN_<name>.py`, chứa danh sách `Case`:

```python
Case(id="T5.9", actor="alice", kind="probe",
     url="https://downloads.lab.test/files/eicar.com",
     expect="ALLOW", limitation=True,
     state={"tls": "splice"},
     expect_issuer=None, priority="P0", note="HTTPS không bump → ICAP không thấy nội dung")
```

- **`actor`:**

  | actor | container | credential | trust |
  |---|---|---|---|
  | `guest` | client-guest | — | chỉ Public CA |
  | `anon` | client-staff | — | Public + Proxy CA |
  | `badpass` | client-staff | `alice:wrong` | Public + Proxy CA |
  | `alice`, `bob`, `admin1` | client-staff | theo §4 | Public + Proxy CA |
  | `alice-unmanaged` | client-staff | alice | `--cacert lab-public-ca.crt` (giả lập thiết bị chưa cài Proxy CA) |

- **`kind`:**
  - `probe`: một lần probe.
  - `probe_sample`: lấy N host ngẫu nhiên (seed cố định) từ một file list, probe từng host với `--dryrun`. PASS khi tỉ lệ khớp `expect` đạt ≥ `min_rate` (mặc định 1.0).
  - `logcheck`: kiểm tra dòng log của một test ID khác theo field/regex.
  - `cmd`: chạy lệnh trong container và kiểm tra exit code / output.
  - `sni_probe`: `openssl s_client -proxy <proxy> -connect <host>:443 -servername <sni>`.
  - `repeat`: probe 2 lần cùng URL, so sánh `%Ss` và thời gian.
- **`state`:** các key `tls` (splice|bump|selective), `worktime` (real|always|never), `icap_bypass` (on|off), `icap_running` (bool).
  - Trạng thái mặc định của mỗi scenario: `tls=selective`, `worktime=never`, `icap_bypass=off`, `icap_running=true`.
  - Runner gom các case cùng state để hạn chế số lần reconfigure, và **khôi phục mặc định** sau mỗi scenario.
- **Status mỗi case:**
  - `PASS`
  - `PASS (limitation)`: kết quả khớp `expect` và `limitation=True`, tức là chứng minh được một giới hạn.
  - `FAIL`
  - `SKIP` (kèm lý do, vd feed rỗng)
- **Evidence:** sau mỗi probe, runner tìm dòng tương ứng trong `access_lab.log` theo test id. Có thể retry tới 2 giây. Lấy `%Ss/%>Hs`, `policy`, `bump_mode` gắn vào cột evidence.
- **Output:**
  - `results/<YYYYmmdd-HHMMSS>/results.csv` và `results.md`, với bảng: ID | Scenario | Actor | URL | State | Expected | Observed | Status | Evidence.
  - Tạo symlink `results/latest`.
  - Exit code khác 0 nếu có FAIL.

---

## 12. Threat feed và category (`scripts/update_feeds.py`)

### 12.1 Nguồn

| Nguồn | URL **[VERIFY tất cả]** | Đầu ra |
|---|---|---|
| URLhaus hostfile (abuse.ch) | `https://urlhaus.abuse.ch/downloads/hostfile/` | `feeds/malware.txt` (host), `feeds/threat_ips.txt` (IP) |
| OpenPhish community | `https://openphish.com/feed.txt` | `feeds/phishing.txt` (hostname trích từ URL) |
| UT1 (Univ. Toulouse Capitole) | `https://dsi.ut-capitole.fr/blacklists/download/<cat>.tar.gz` | `feeds/ut1_<cat>.txt` |

- **Category UT1 mặc định:** `gambling`, `games`, `social_networks`, `phishing`, `malware`.
  - `adult` không bật mặc định vì quá lớn. Có thể bật qua biến `UT1_CATEGORIES`.
- Nếu abuse.ch yêu cầu Auth-Key thì đọc từ biến `ABUSECH_AUTH_KEY`.

### 12.2 Quy tắc chuẩn hóa

- Chuyển về chữ thường, trim, bỏ comment và dòng trống, bỏ dấu `.` ở cuối. IDN chuyển sang punycode. Validate theo regex hostname.
- **IP:** với threat feed thì ghi vào `threat_ips.txt`. Với category thì bỏ qua.
- **Phishing/URLhaus:** dùng **exact host** (không có `.` đầu), để không chặn nhầm cả nền tảng shared hosting. **UT1:** dùng `.domain`.
- **Lọc qua allowlist:** loại các entry khớp `never_block.txt` và đếm số entry bị loại. Đây là số liệu cho phần đánh giá trade-off FP/FN.
- **Khử trùng lặp:** bỏ entry trùng và entry đã được một `.parent` trong cùng file bao phủ (nếu không, Squid sẽ cảnh báo).
- **Ghi file an toàn:** ghi atomic (file tạm rồi rename). Nếu tải lỗi thì **giữ file cũ**.
- **Thống kê:** ghi số liệu ra `results/feeds_stats.json` (số entry, số bị loại, thời điểm).
- **Snapshot:** lưu bản sao theo ngày vào `policy/lists/feeds/snapshots/<YYYY-MM-DD>/`, phục vụ đánh giá độ tươi của feed.
- Đặt `User-Agent: NT140-lab-feed-updater`.
- **Tuyệt đối không fetch URL nằm trong feed.**
- Sau khi cập nhật xong, chạy `squid -k reconfigure`.

### 12.3 Dryrun an toàn

Mục đích: kiểm tra một host trong feed có bị chặn hay không, mà **không** để proxy kết nối tới host độc hại.

```squid
acl dryrun req_header X-Lab-Dryrun -i ^1$
never_direct allow dryrun        # (conf.d/14-dryrun.conf) không có cache_peer → request không bị chặn sẽ trả 503, không ra Internet
```

- Request bị chặn thì nhận 403 (`BLOCK`). Request lọt qua thì nhận 503 (`UPSTREAM_ERROR`), tức là FAIL với các case kiểu blocklist.
- Dryrun chỉ dùng được với URL `http://`.

### 12.4 Đánh giá

- `scripts/eval_fp.py`:
  - Tải Tranco top-N (mặc định N = 10000, `https://tranco-list.eu/top-1m.csv.zip` **[VERIFY]**).
  - Giao **offline** (theo đúng ngữ nghĩa `dstdomain`) với từng blocklist.
  - Xuất `results/eval_fp.md`: số domain phổ biến bị chặn theo từng list kèm ví dụ (ứng viên false positive).
- `scripts/eval_feed_freshness.py` (P2): so sánh 2 snapshot, đo tỉ lệ entry mới, từ đó ước lượng một blocklist “đứng yên” bỏ sót bao nhiêu.
- `scripts/eval_coverage.py` (P2): đo tỉ lệ host của OpenPhish/URLhaus có mặt trong UT1 `phishing`/`malware`, để cho thấy khoảng trống khi chỉ dùng một list tĩnh.

---

## 13. Kịch bản kiểm thử (acceptance)

Ký hiệu:
- `[L]`: case có `limitation=True`, tức kết quả mong đợi là chứng minh một giới hạn.
- State không ghi thì dùng mặc định (§11).

### S0. Smoke (P0)

| ID | Kind | Mô tả | Expect |
|---|---|---|---|
| T0.1 | cmd squid | `squid -k parse` | exit 0, không có `ERROR` |
| T0.2 | cmd squid | `squid -v` | chứa `--with-openssl` |
| T0.3 | cmd icap | gửi ICAP OPTIONS tới `virus_scan` (vd `c-icap-client`) **[VERIFY]** | 200 |
| T0.4 | cmd clamav | ping clamd | PONG |
| T0.5 | cmd squid | `curl` trực tiếp `http://allowed.lab.test/` | 200 |
| T0.6 | cmd client-staff | `ip route` | **không** có default route |

### S1. Chính sách theo network (P0)

| ID | Actor | URL | Expect |
|---|---|---|---|
| T1.1 | guest | http://allowed.lab.test/ | ALLOW |
| T1.2 | guest | http://social.lab.test/ | BLOCK:social |
| T1.3 | guest | http://games.lab.test/ | BLOCK:games |
| T1.4 | guest | http://stream.lab.test/ | BLOCK:streaming |
| T1.5 | guest | https://social.lab.test/ | BLOCK:social (tại CONNECT) |
| T1.6 | guest | http://gamble.lab.test/ | BLOCK:gambling |
| T1.7 | alice | http://social.lab.test/ | ALLOW (ngoài giờ) |
| T1.8 | anon | http://allowed.lab.test/ | AUTH_REQUIRED (staff net bắt buộc auth, guest net thì không) |

### S2. Chính sách theo user/group/time (P0)

| ID | Actor | URL | State | Expect |
|---|---|---|---|---|
| T2.1 | badpass | http://allowed.lab.test/ | | AUTH_REQUIRED |
| T2.2 | alice | http://allowed.lab.test/ | | ALLOW |
| T2.3 | logcheck | dòng log của T2.2 | | field user = `alice` |
| T2.4 | alice | http://social.lab.test/ | worktime=always | BLOCK:worktime |
| T2.5 | alice | https://social.lab.test/ | worktime=always | BLOCK:worktime |
| T2.6 | bob | http://games.lab.test/ | worktime=always | BLOCK:worktime |
| T2.7 | admin1 | http://social.lab.test/ | worktime=always | ALLOW |
| T2.8 | alice | http://social.lab.test/ | worktime=never | ALLOW |
| T2.9 | alice | http://gamble.lab.test/ | | BLOCK:gambling |
| T2.10 | admin1 | http://gamble.lab.test/ | | ALLOW |

### S3. Lọc theo category bằng blacklist UT1 (P1, SKIP nếu feed rỗng)

| ID | Kind | Mô tả | Expect |
|---|---|---|---|
| T3.1 | probe_sample | guest, 20 host từ `ut1_gambling.txt`, dryrun | BLOCK:gambling, 100% |
| T3.2 | probe_sample | guest, 20 host từ `ut1_social_networks.txt` | BLOCK:social, 100% |
| T3.3 | probe_sample | guest, 20 host từ `ut1_games.txt` | BLOCK:games, 100% |
| T3.4 | cmd labvm | chạy `eval_fp.py` | sinh `eval_fp.md` (chỉ báo cáo, không pass/fail theo số liệu) |

### S4. Chống phishing và domain độc hại (P0; T4.5–T4.6 là P1)

| ID | Actor | URL | Expect |
|---|---|---|---|
| T4.1 | alice | http://uitbank-secure-login.lab.test/login | BLOCK:phishing |
| T4.2 | admin1 | http://uitbank-secure-login.lab.test/login | BLOCK:phishing (threat áp cho cả admin) |
| T4.3 | guest | https://uitbank-secure-login.lab.test/login | BLOCK:phishing |
| T4.4 | alice | http://uitbank.lab.test/ | ALLOW (không chặn nhầm site thật) |
| T4.5 | alice | probe_sample 20 host từ `feeds/phishing.txt`, dryrun | BLOCK:phishing, 100% |
| T4.6 | alice | probe_sample 20 host từ `feeds/malware.txt`, dryrun | BLOCK:malware, 100% |
| T4.7 | alice | http://malware-cdn.lab.test/payload.bin | BLOCK:malware |
| T4.8 | alice | http://uitbank-verify-account.lab.test/login | ALLOW [L]: phishing zero-day chưa có trong feed |

### S5. Quét file tải xuống bằng ICAP/ClamAV (P0)

| ID | Actor | URL (`downloads.lab.test`) | State | Expect |
|---|---|---|---|---|
| T5.1 | alice | http …/files/eicar.com | | BLOCK:malware-content |
| T5.2 | alice | http …/files/eicar.zip | | BLOCK:malware-content |
| T5.3 | alice | http …/files/eicar-nested.zip | | BLOCK:malware-content |
| T5.4 | alice | http …/files/eicar-encrypted.zip | | ALLOW [L] |
| T5.5 | alice | http …/files/eicar-big.zip | | ALLOW [L]: vượt MaxObjectSize |
| T5.6 | alice | http …/files/clean.pdf | | ALLOW (không chặn nhầm) |
| T5.7 | admin1 | http …/files/eicar.com | | BLOCK:malware-content |
| T5.8 | guest | http …/files/eicar.com | | BLOCK:malware-content |
| T5.9 | alice | https …/files/eicar.com | tls=splice | ALLOW [L] |
| T5.10 | alice | https …/files/eicar.com | tls=selective | BLOCK:malware-content |
| T5.11 | guest | https …/files/eicar.com | tls=selective | ALLOW [L]: BYOD được splice |
| T5.12 | alice | http …/files/eicar.com | icap_running=false, icap_bypass=off | UPSTREAM_ERROR (fail-closed) |
| T5.13 | alice | http …/files/eicar.com | icap_running=false, icap_bypass=on | ALLOW [L]: fail-open |

### S6. Chặn loại file (P1)

| ID | Actor | URL (`downloads.lab.test`) | State | Expect |
|---|---|---|---|---|
| T6.1 | alice | http …/files/setup.exe | | BLOCK:filetype |
| T6.2 | alice | http …/files/invoice.pdf.exe | | BLOCK:filetype |
| T6.3 | alice | http …/dl/a1b2c3 | | BLOCK:filetype-mime |
| T6.4 | alice | http …/files/renamed-exe.txt | | ALLOW [L]: không nhận diện magic bytes |
| T6.5 | admin1 | http …/files/setup.exe | | ALLOW |
| T6.6 | guest | http …/files/app.apk | | BLOCK:filetype |
| T6.7 | alice | https …/files/setup.exe | tls=splice | ALLOW [L] |
| T6.8 | alice | https …/files/setup.exe | tls=selective | BLOCK:filetype |

### S7. HTTPS không giải mã: splice (P0, state tls=splice)

| ID | Actor / kind | Mô tả | Expect |
|---|---|---|---|
| T7.1 | alice, worktime=always | https://social.lab.test/ | BLOCK:worktime (domain vẫn thấy được qua CONNECT) |
| T7.2 | alice | http://allowed.lab.test/upload | BLOCK:path |
| T7.3 | alice | https://allowed.lab.test/upload | ALLOW [L]: không thấy path |
| T7.4 | alice | https://allowed.lab.test/ | ALLOW, issuer = Lab Public Root CA |
| T7.5 | logcheck | dòng log của T7.4 | method `CONNECT`, URL `allowed.lab.test:443`, `%Ss`=`TCP_TUNNEL`, bump_mode `splice` |
| T7.6 | sni_probe | CONNECT `allowed.lab.test:443`, SNI `uitbank-secure-login.lab.test` | TLS_ERROR (terminate), log policy=`sni-threat` |
| T7.7 | alice | https://pinned.lab.test/ `--pinned` | ALLOW |
| T7.8 | repeat | alice, https://cache.lab.test/cacheable/\<runid\>/1m.bin, 2 lần | lần 2 **không** HIT [L] |

### S8. HTTPS có giải mã chọn lọc: selective bump (P0, state tls=selective)

| ID | Actor / kind | Mô tả | Expect |
|---|---|---|---|
| T8.1 | alice | https://allowed.lab.test/ | ALLOW, issuer = SWG Proxy CA |
| T8.2 | alice | https://allowed.lab.test/upload | BLOCK:path |
| T8.3 | alice | https://uitbank.lab.test/ | ALLOW, issuer = Lab Public Root CA (nobump) |
| T8.4 | guest | https://allowed.lab.test/ | ALLOW, issuer = Lab Public Root CA (BYOD splice) |
| T8.5 | alice | https://pinned.lab.test/ `--pinned` | TLS_ERROR [L]: bump làm hỏng certificate pinning |
| T8.6 | alice-unmanaged | https://allowed.lab.test/ | TLS_ERROR (thiết bị chưa cài Proxy CA) |
| T8.7 | repeat | alice, https://cache.lab.test/cacheable/\<runid\>/1m.bin, 2 lần | lần 2 là `TCP_HIT` hoặc `TCP_MEM_HIT` |
| T8.8 | logcheck | dòng log của T8.1 | method `GET`, URL đầy đủ `https://allowed.lab.test/`, bump_mode `bump` |
| T8.9 | guest, tls=bump | https://allowed.lab.test/ | TLS_ERROR (bump toàn bộ làm hỏng BYOD) |

### S9. Chống bypass và hardening (P1)

| ID | Actor / kind | Mô tả | Expect |
|---|---|---|---|
| T9.1 | alice `--direct` | http://allowed.lab.test/ | CONN_FAIL |
| T9.2 | alice `--direct` | https://1.1.1.1/ | CONN_FAIL |
| T9.3 | alice | https://allowed.lab.test:8443/ | BLOCK:default (CONNECT tới port ngoài SSL_ports) |
| T9.4 | alice | http://172.30.0.50/ | BLOCK:ip-literal |
| T9.5 | admin1 | http://172.30.0.50/ | ALLOW |
| T9.6 | alice | https://dns.lab.test/dns-query?name=example.com | BLOCK:doh |
| T9.7 | alice | https://cloudflare-dns.com/dns-query | BLOCK:doh (bị chặn tại CONNECT, không ra Internet) |
| T9.8 | cmd client-staff | gửi UDP tới 1.1.1.1:443 (giả lập QUIC) | lỗi `Network unreachable` |
| T9.9 | P2, alice | CONNECT `tcpecho.lab.test:443`, gửi dữ liệu không phải TLS | kết nối bị đóng hoặc nhận lỗi (on_unsupported_protocol) |

ECH và VPN/Tor: phân tích lý thuyết trong `docs/tls-limitations.md` (§16), không cần test tự động. Luận điểm chính: với explicit proxy, CONNECT vẫn lộ hostname dù có ECH. ECH chủ yếu vô hiệu hóa việc lọc theo SNI trong transparent mode và trên firewall.

### S10. Cache và băng thông (P1)

| ID | Actor / kind | Mô tả | Expect |
|---|---|---|---|
| T10.1 | repeat, alice | http://cache.lab.test/cacheable/\<runid\>/10m.bin | lần 1 MISS, lần 2 HIT; ghi lại thời gian 2 lần |
| T10.2 | repeat, alice | http://cache.lab.test/nocache/1m.bin | cả 2 lần đều không HIT |
| T10.3 | guest | http://cache.lab.test/cacheable/\<runid\>/2m.bin | `speed` ≤ 1.2 × `GUEST_RATE_BYTES` |
| T10.4 | alice | cùng URL với T10.3 | `speed` > 4 × `GUEST_RATE_BYTES` |

### S11. Audit và logging (P0)

| ID | Kind | Mô tả | Expect |
|---|---|---|---|
| T11.1 | logcheck toàn bộ | mọi dòng `TCP_DENIED/403` do policy có test id trong lần chạy | field `policy` không rỗng |
| T11.2 | cmd labvm | chạy `log_summary.py` | sinh `log_summary.md`, có cache hit ratio và thống kê theo policy |
| T11.3 | logcheck | toàn bộ log | không chứa `Proxy-Authorization` hoặc mật khẩu lab |

### 13.1 Benchmark (`scripts/bench.sh` gọi `scripts/bench.py`)

- Mỗi cấu hình chạy N = 50 request (cấu hình được) cho 2 loại payload: trang 1 KB (`/`) và file 1 MB (`/cacheable/<runid>/1m.bin`). Tính avg/p50/p95 của `time_total`.
- Lấy mẫu CPU/MEM bằng `docker stats --no-stream`.

| # | Cấu hình |
|---|---|
| B1 | Trực tiếp, HTTP (chạy curl từ container `squid` tới testweb) |
| B2 | Qua proxy, HTTP, cache MISS (path mới mỗi lần) |
| B3 | Qua proxy, HTTP, cache HIT |
| B4 | Qua proxy, HTTP, MISS, có ICAP |
| B5 | Trực tiếp, HTTPS |
| B6 | Qua proxy, HTTPS splice |
| B7 | Qua proxy, HTTPS bump |
| B8 | Qua proxy, HTTPS bump + ICAP |

- Để đo B2/B3/B6/B7 “không ICAP”, runner tạm thời đặt `adaptation_access svc_av deny all` qua biến `ICAP_ENABLED=0` rồi reconfigure.
- Output: `results/bench/<ts>/bench.csv` và `bench.md`.

---

## 14. Stretch (P2)

Xếp theo mức độ giá trị:
1. **Transparent intercept:**
   - `https_port 3130 intercept ssl-bump` và iptables/nft REDIRECT trong container squid (`cap_add: NET_ADMIN`).
   - Client đặt default route trỏ về squid khi `CLIENT_MODE=transparent`.
   - Thêm container DNS (dnsmasq/unbound) cho LAN.
   - So sánh với explicit proxy: lọc theo SNI, ảnh hưởng của ECH, không còn bước 407.
2. **Client có GUI:** Firefox trong container (vd `lscr.io/linuxserver/firefox`), dùng enterprise policy để khóa proxy và cài Proxy CA. Mục đích là demo trình duyệt. Phải ghi rõ client này không bị cô lập egress.
3. **OpenLDAP:** `basic_ldap_auth` và `ext_ldap_group_acl`.
4. **Test tunnel không phải TLS** (T9.9) với `tcpecho`.
5. **ClamAV `AlertEncrypted yes`:** đo lại T5.4.
6. **ufdbGuard:** so sánh với `dstdomain` khi list lớn (UT1 adult), đo thời gian load và RAM.
7. **Loki + Grafana:** thay thế GoAccess.

---

## 15. Cấu trúc repo

```
project_nt140/
├── CLAUDE.md  plan.md  spec.md  README.md  Makefile  .env.example  .gitignore  docker-compose.yml
├── docker/
│   ├── squid/   Dockerfile, entrypoint.sh,
│   │            conf/squid.conf (chỉ include theo thứ tự),
│   │            conf/conf.d/{00-base,10-acl-network,11-acl-lists,12-acl-auth,13-acl-misc,14-dryrun,
│   │                         40-access,41-reply-access,50-cache,51-delay,60-logging,70-errors}.conf,
│   │            templates/{sslbump-splice,sslbump-bump,sslbump-selective,icap,delay}.conf.tmpl,
│   │            errors/ERR_LAB_*
│   ├── icap/    Dockerfile, entrypoint.sh, c-icap.conf, virus_scan.conf, clamd_mod.conf, templates/VIRUS_FOUND
│   ├── testweb/ Dockerfile, nginx.conf, entrypoint.sh (sinh file test), html/
│   └── client/  Dockerfile, entrypoint.sh
├── policy/
│   ├── auth/users.lab
│   ├── lists/local/*.txt
│   ├── lists/feeds/            (gitignored; có .gitkeep)
│   └── generated/              (gitignored: work_hours.conf …)
├── certs/                      (gitignored trừ README.md)
├── scripts/  gen-certs.sh  set-tls-mode.sh  set-worktime.sh  set-icap.sh  capture.sh  bench.sh
│             update_feeds.py  log_summary.py  eval_fp.py  bench.py  eval_feed_freshness.py  eval_coverage.py
├── tests/    run_all.py  lib/ (case model, docker helpers, log parser)  scenarios/s00_smoke.py … s11_logging.py
│             probe/probe.sh
├── logs/  captures/  results/  (gitignored)
└── docs/     architecture.md  policy-matrix.md  scenarios.md  tls-limitations.md  wireshark.md
              demo-runbook.md  verify-log.md  open-questions.md  progress.md  report/outline.md
```

**Mount cố định (host → container):**

| Host | Container | Chế độ |
|---|---|---|
| `./policy` | squid `/etc/squid/policy` | ro |
| `./certs` | squid, client, testweb `/opt/certs` | ro. Squid copy key sang `/etc/squid/ssl/` (§3) |
| `./logs/squid` | squid `/var/log/squid` | rw |
| `./tests/probe` | client `/opt/lab` | ro |
| `./captures` | client, sniffer `/captures` | rw |
| volume `squid-cache` | squid `/var/spool/squid` | rw |
| volume `squid-ssldb` | squid `/var/lib/squid/ssl_db` | rw |

File sinh trong container squid: `/etc/squid/auth/{users.htpasswd,group_admin.txt,group_staff.txt}` (§4), `/etc/squid/conf.d/{20-sslbump,30-icap,51-delay}.conf` (render từ template).

**Render cấu hình:**
- Entrypoint của squid render `*.conf.tmpl` bằng `envsubst`, với **whitelist biến**: `TLS_MODE`, `ICAP_BYPASS_FLAG`, `ICAP_ENABLED`, `GUEST_RATE_BYTES`.
- Lý do: Squid không tự đọc biến môi trường trong `squid.conf`.
- Sau khi render, chạy `squid -k parse` trước khi start. Nếu parse lỗi thì thoát với mã khác 0.
- **Tài liệu tra cứu trong image:** trước khi ghi đè `squid.conf`, Dockerfile của squid phải copy file `/etc/squid/squid.conf` gốc (bản có comment đầy đủ của gói Ubuntu) sang `/usr/share/doc/nt140/squid.conf.documented` **[VERIFY]**. Đây là tài liệu dùng để tra cứu directive đúng với phiên bản đang cài.

**`.env.example`:**

```
TZ=Asia/Ho_Chi_Minh
PUBLISH_ADDR=127.0.0.1
TLS_MODE=selective
WORK_HOURS_MODE=real
ICAP_BYPASS=off
ICAP_ENABLED=1
GUEST_RATE_BYTES=262144
UT1_CATEGORIES=gambling games social_networks phishing malware
ABUSECH_AUTH_KEY=
```

**`.gitignore`** tối thiểu: `.env`, `CLAUDE.local.md`, `certs/*` (trừ `certs/README.md`), `policy/lists/feeds/*` (trừ `.gitkeep`), `policy/generated/`, `logs/`, `captures/`, `results/`, `*.pcap`, `*.keys`, `__pycache__/`.

**Makefile targets:**

| Target | Việc |
|---|---|
| `help` | liệt kê target |
| `init` | gen-certs, tạo thư mục, feed rỗng, work_hours, copy `.env.example` sang `.env` nếu chưa có |
| `build` / `up` / `down` / `ps` / `logs` | compose |
| `clean` | `down -v` và xóa logs/results (có hỏi xác nhận) |
| `reconfigure` | `squid -k reconfigure` |
| `tls-mode MODE=…` / `worktime MODE=…` / `icap-bypass MODE=on\|off` | đổi state |
| `feeds` | `update_feeds.py` rồi reconfigure |
| `test` / `test S=S5` / `test P=P0` | test runner |
| `bench` / `summary` / `eval-fp` | đánh giá |
| `capture NAME=… SECS=…` | pcap |
| `shell-staff` / `shell-guest` / `shell-squid` | `docker compose exec … bash` |

---

## 16. Tài liệu (`docs/`)

Phần chữ viết bằng tiếng Việt. Thuật ngữ kỹ thuật giữ nguyên tiếng Anh.

| File | Nội dung |
|---|---|
| `architecture.md` | Sơ đồ Mermaid (topology và luồng §2.4), vai trò từng service, bảng IP |
| `policy-matrix.md` | Ma trận §5.3, kèm trích dòng `http_access` tương ứng |
| `scenarios.md` | Với mỗi S1–S11: mục tiêu, cấu hình liên quan, cách chạy, bảng kết quả (lấy từ `results/latest`), nhận xét, chỗ chèn ảnh |
| `tls-limitations.md` | splice vs bump; SNI; TLS 1.3; **ECH**; **QUIC/HTTP3**; **DoH**; certificate pinning; HSTS; ảnh hưởng hiệu năng; quyền riêng tư và pháp lý khi giải mã TLS (để nhóm bổ sung trích dẫn quy định của VN); khuyến nghị (selective bump, egress firewall, chặn UDP 443, chặn DoH, quản lý endpoint) |
| `wireshark.md` | Hướng dẫn capture, filter, cách giải mã bằng SSLKEYLOGFILE / `tls_key_log` |
| `demo-runbook.md` | Kịch bản demo trực tiếp khoảng 10 phút, liệt kê từng lệnh |
| `report/outline.md` | Dàn ý báo cáo: 1. Tổng quan · 2. Cơ sở lý thuyết · 3. Thiết kế · 4. Triển khai · 5. Kịch bản & đánh giá · 6. Giới hạn & thảo luận · 7. Kết luận & hướng phát triển |
| `verify-log.md` / `open-questions.md` / `progress.md` | Nhật ký làm việc (xem `plan.md`) |

---

## 17. Definition of Done toàn dự án

1. Từ một bản clone sạch, `make init && make up` đưa mọi service về trạng thái healthy trong ≤ 10 phút (bao gồm thời gian tải signature ClamAV).
2. `make test` cho kết quả **tất cả case P0 đều PASS** trên **cả hai kiến trúc**: arm64 (Lab VM trên UTM/M2) và amd64. Case P1 phải PASS, hoặc SKIP kèm lý do rõ ràng (vd không tải được feed).
3. `squid -k parse` không có `ERROR`. `WARNING` được phép nếu đã giải thích trong verify-log.
4. File `results.md` được sinh tự động, có ≥ 80 case, phủ ≥ 10 scenario.
5. `make bench`, `make summary`, `make eval-fp` đều sinh ra file kết quả.
6. Thư mục `docs/` có đủ các file ở §16.
7. Repo không chứa private key, htpasswd, malware thật, hay chuỗi EICAR nguyên vẹn.
