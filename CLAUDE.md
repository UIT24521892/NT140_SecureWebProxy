# CLAUDE.md: NT140 Secure Web Gateway Lab

Claude Code tự động nạp file này ở **mỗi phiên**. File được giữ ngắn có chủ đích: chi tiết nằm ở `spec.md` (nguồn sự thật kỹ thuật) và `plan.md` (phân công, task, lộ trình). Nếu file này lệch với `spec.md` thì **spec.md đúng**; hãy báo người dùng để sửa file này.

Trạng thái hiện tại của dự án (được import tự động):

@docs/progress.md

---

## 1. Dự án

Đây là lab Docker Compose dựng một **Secure Web Gateway** cho đồ án NT140 (An toàn mạng, UIT), gồm:
- Squid 6 (gói `squid-openssl`) làm forward proxy, có SslBump;
- c-icap + ClamAV quét file tải xuống;
- nginx `testweb` giả lập Internet trên domain `*.lab.test`;
- client `client-staff` (managed) và `client-guest` (BYOD);
- test runner Python sinh bảng kết quả cho các kịch bản **S0–S11**.

Nhóm có 3 người, mỗi người một track: **INF/POL** (TV1, arm64, Docker Desktop trên Mac M2), **TLS** (TV2, amd64), **THR** (TV3, amd64). Xem `plan.md` §2.

Nếu có `CLAUDE.local.md`, file đó cho biết người đang làm việc với bạn là ai và thuộc track nào. Nếu không có file này và task chưa nói rõ track, **hãy hỏi**.

## 2. Quy trình bắt buộc mỗi phiên

1. **Nắm trạng thái từ file, không dựa vào trí nhớ.** Đọc `docs/progress.md` (đã import ở trên). Kiểm tra trạng thái thật bằng `git status`, `git log --oneline -5`, `docker compose ps`.
2. **Xác định task ID** (vd `TLS-3`) trong `plan.md` §6. Nếu người dùng không nêu task, hỏi lại.
3. **Đọc đúng mục spec trước khi viết code hay config** (bảng §4 bên dưới). Dùng `grep -n '^##' spec.md` để định vị, chỉ đọc phần cần. Không viết config từ trí nhớ.
4. **Lập kế hoạch ngắn** (các bước, file sẽ sửa, lệnh kiểm tra), rồi mới làm. Với task nhiều bước, ghi checklist vào section track của mình trong `docs/progress.md` và đánh dấu dần, để phiên sau có thể làm tiếp.
5. **Chỉ sửa file thuộc track của task** (`plan.md` §2.1). Nếu buộc phải sửa file của track khác, nói rõ lý do và ghi vào mô tả PR.
6. **Kiểm tra** theo §5 và dán **output thật**.
7. **Kết thúc phiên:**
   - Ghi đè section track của mình trong `docs/progress.md`: task, đã xong gì, lệnh test và kết quả, bước tiếp, blocker.
   - Toàn file `progress.md` giữ ≤ 100 dòng.
   - Chỉ commit khi người dùng đồng ý. Không push lên `main`, không merge PR.

## 3. Chống ảo giác: quy tắc cứng

- **Không bao giờ nói “đã chạy”, “đã pass”, “hoạt động”** nếu chưa thực sự chạy lệnh trong phiên này. Luôn kèm lệnh và output (rút gọn được). Fail thì nói fail, kèm lỗi.
- **Không sửa `expect` của test cho khớp với kết quả.** Nếu thực tế khác spec: dừng lại, báo người dùng, ghi vào `docs/open-questions.md` (nếu là vấn đề ngữ nghĩa policy) hoặc `docs/verify-log.md` (nếu là khác biệt phần mềm), rồi chờ người dùng quyết định.
- Case có `limitation=True` / `[L]` **cố ý** mong đợi ALLOW hoặc lỗi, để chứng minh giới hạn. Đó không phải bug, không được “sửa” thành BLOCK.
- **Kiểm chứng trước khi dùng** mọi directive, option, tên module, image tag hay URL không có sẵn trong spec. Cách kiểm chứng:
  - **Directive Squid:** `docker compose exec squid grep -n -A20 '^#  TAG: <directive>' /usr/share/doc/nt140/squid.conf.documented`, sau đó chạy `docker compose exec squid squid -k parse`.
  - **c-icap:** đọc file cấu hình mẫu có comment trong `/etc/c-icap/` của image `icap`, và liệt kê module thật đang có trong image.
  - **ClamAV:** chạy `clamconf` hoặc đọc file `clamd.conf` mẫu trong image `clamav`.
  - **Image:** `docker buildx imagetools inspect <image:tag>` phải có **cả** `linux/arm64` và `linux/amd64`.
  - **URL nguồn** (feed, tài liệu): `curl -sSI <url> | head -5`. Tuyệt đối không áp dụng cho host lấy từ trong feed.
- **Mục `[VERIFY]` trong spec:** kiểm chứng xong mà thực tế khác, thì làm theo thực tế, thêm 1 dòng vào `docs/verify-log.md` (mục, spec giả định, thực tế kèm bằng chứng, quyết định), rồi sửa `spec.md` **trong cùng PR**. Không sửa spec vì lý do nào khác nếu người dùng chưa đồng ý.
- **Không chắc thì nói không chắc**, kèm cách kiểm chứng. Không tự chọn ngữ nghĩa policy (ai bị chặn cái gì). Ma trận ở spec §5.3 là chuẩn.
- **Không đổi** tên ACL, reason, outcome, test ID, service, IP, đường dẫn (bảng §6) mà không cập nhật spec.

### Những điểm dễ sai đã biết trong dự án này

- Trên Ubuntu phải dùng **`squid-openssl`**. Gói `squid` thường không có SslBump. Kiểm tra: `squid -v | grep -- --with-openssl`.
- SslBump dùng `at_step` với các action `peek`/`stare`/`splice`/`bump`/`terminate`. **Không** dùng `server-first`/`client-first`/`none` (cú pháp cũ). **Không** thêm `peek step2` trước `bump`, vì peek ở step2 thường khiến không bump được nữa.
- Cấu hình TLS phía upstream dùng `tls_outgoing_options`. Không dùng các directive `sslproxy_flags`/`sslproxy_cafile` kiểu cũ.
- Không giả định Squid đọc biến môi trường trong `squid.conf`. Lab render `*.conf.tmpl` bằng `envsubst` với whitelist biến (spec §15).
- Quét virus dùng service **`virus_scan` + `clamd_mod`** của c-icap-modules. **Không** dùng squidclamav.
- `http_access` là **first-match**. Thứ tự đã cố định ở spec §5.4, **không được sắp xếp lại**.
- `deny_info` gắn vào **ACL cuối cùng** của dòng deny, nên mọi dòng deny phải kết thúc bằng `mark_<reason>`.
- File ACL không tồn tại sẽ làm Squid fatal. Feed rỗng phải được `make init` tạo sẵn.
- `refresh_pattern` mặc định không cache URL có `?`. Test cache phải dùng path duy nhất `/cacheable/<runid>/…`, không dùng query string.
- Ở mode splice, proxy **không** thấy path, **không** quét được file, **không** cache được HTTPS. Đây là kết quả mong đợi.
- Network `internal: true` không có default route. Client gọi thẳng ra ngoài phải ra `CONN_FAIL`. Port publish chỉ chạy qua network `wan`.
- Lab chạy trên **2 kiến trúc**. Không dùng `platform: linux/amd64`, không dùng QEMU emulation. Image thiếu arm64 thì dùng phương án trong spec.

## 4. Bản đồ tài liệu: muốn làm gì thì đọc mục nào

| Việc | Đọc |
|---|---|
| Service, network, IP, domain `*.lab.test`, luồng request | spec §2 |
| CA, cert, pinning | spec §3 |
| User, nhóm, auth | spec §4 |
| List, ACL, ma trận policy, thứ tự `http_access`, trang chặn, giờ làm, băng thông, cache | spec §5.1–§5.8 |
| SslBump, `TLS_MODE`, hành vi theo mode | spec §6 |
| ICAP, ClamAV, fail-open/fail-closed | spec §7 |
| Path và file của testweb | spec §8 |
| Client, hợp đồng JSON của `probe.sh` | spec §9 |
| Logformat `lab`, log summary, dashboard, capture | spec §10 |
| Test runner: `Case`, actor, kind, state, output | spec §11 |
| Feed, chuẩn hóa, dryrun, đánh giá FP | spec §12 |
| Test case S0–S11, benchmark | spec §13 |
| Stretch | spec §14 |
| Cây repo, mount, render template, `.env`, Makefile | spec §15 |
| Tài liệu cần viết | spec §16 |
| Definition of Done của dự án | spec §17 |
| Track, quyền sở hữu file, task ID, DoD của task, milestone | plan §2, §5, §6 |
| Môi trường (Docker Desktop / Linux VM / Kali để demo), Claude Code | plan §3 |
| Git, PR, gác cổng 2 kiến trúc | plan §4 |

## 5. Lệnh và kiểm tra

Mọi lệnh chạy tại thư mục gốc repo, trên máy có Docker: macOS + Docker Desktop, Linux, hoặc WSL. Kiến trúc hiện tại xem bằng `uname -m` (`arm64`/`aarch64` hoặc `x86_64`).

Script chạy trên host phải tương thích **bash 3.2/BSD (macOS)** lẫn bash 5/GNU: không dùng `sed -i`, `mapfile`, `grep -P`, `readlink -f`, associative array.

```bash
make init | build | up | down | ps | logs | reconfigure
make test                 # tất cả     | make test S=S5  | make test P=P0
make tls-mode MODE=splice|bump|selective
make worktime MODE=real|always|never
make icap-bypass MODE=on|off
make feeds | bench | summary | eval-fp | capture NAME=x SECS=30
make shell-staff | shell-guest | shell-squid
```

Trước khi báo task xong, phải chạy **tối thiểu**:

1. Có sửa cấu hình squid: `docker compose exec squid squid -k parse`, không có `ERROR`/`FATAL`.
2. Chạy `make test S=<scenario của task>`. Nếu có sửa phần dùng chung (compose, `40-access.conf`, entrypoint squid, probe, runner) thì chạy thêm `make test P=P0`.
3. Chạy `shellcheck` với các `.sh` đã sửa, `python3 -m py_compile` với các `.py` đã sửa.
4. Có sửa Dockerfile/compose: chạy `make build`, rồi nêu rõ đã test trên kiến trúc nào và cần người ở kiến trúc còn lại kiểm (plan §4.2).
5. Đối chiếu với DoD của task trong `plan.md` §6.

**Lệnh phá hủy phải hỏi trước:** `make clean`, `docker compose down -v`, `docker system prune`, `git reset --hard`, `git push --force`, và `rm -rf` ngoài `results/`, `logs/`.

## 6. Giá trị cố định (tra nhanh, chuẩn nằm ở spec)

- **Service / IP:**
  - `squid`: 10.10.0.10 / 10.20.0.10 / 10.30.0.10 / 172.30.0.10
  - `client-staff`: 10.10.0.101
  - `client-guest`: 10.20.0.101
  - `icap`: 10.30.0.20
  - `clamav`: 10.30.0.21 / 172.30.0.21
  - `testweb`: 172.30.0.50
  - `goaccess`: 172.30.0.60
  - `sniffer`, `tcpecho`: P1/P2
- **Network:** `lan_staff` 10.10.0.0/24, `lan_guest` 10.20.0.0/24, `svc` 10.30.0.0/24 (cả 3 đều internal), `wan` 172.30.0.0/24.
- **Port:** squid 3128 (explicit + ssl-bump), 3129/3130 (intercept, P2), ICAP 1344 (service `virus_scan`), clamd 3310, goaccess 7890. Mặc định chỉ publish trên 127.0.0.1 của host (`PUBLISH_ADDR` trong `.env`).
- **Image ClamAV:** `clamav/clamav-debian:1.4`. Bản `clamav/clamav` (Alpine) không có arm64.
- **Outcome:** `ALLOW` `BLOCK` `AUTH_REQUIRED` `TLS_ERROR` `CONN_FAIL` `UPSTREAM_ERROR`.
- **Status:** `PASS` · `PASS (limitation)` · `FAIL` · `SKIP`.
- **Reason:** `phishing` `malware` `doh` `ip-literal` `gambling` `social` `games` `streaming` `worktime` `path` `filetype` `filetype-mime` `malware-content` `sni-threat` `default`. Template tương ứng là `ERR_LAB_<REASON>`, viết hoa, `-` đổi thành `_`.
- **Biến môi trường:** `TLS_MODE` = `splice` | `bump` | `selective` (mặc định); `WORK_HOURS_MODE` = `real` | `always` | `never`; `ICAP_BYPASS` = `off` (mặc định) | `on`.
- **Tài khoản lab:** `alice`/`alice123` (staff), `bob`/`bob123` (staff), `admin1`/`admin123` (admin).
- **CA:** `CN=NT140 Lab Public Root CA` (mọi máy tin), `CN=NT140 SWG Proxy CA` (chỉ `client-staff` tin).
- **Marker / header:**
  - marker trong trang: `<!-- LAB-BLOCK reason=… -->`, `<!-- LAB-ORIGIN host=… -->`
  - header: `X-Lab-Test-Id`, `X-Lab-Dryrun: 1`
- **Đường dẫn trong container:** `/etc/squid/policy` (ro), `/etc/squid/auth`, `/etc/squid/ssl`, `/var/lib/squid/ssl_db`, `/var/log/squid`, `/usr/share/doc/nt140/squid.conf.documented`, `/opt/lab/probe.sh`, `/opt/certs`, `/captures`.

## 7. An toàn (không có ngoại lệ)

- Không tải, tạo hay chạy malware thật. Chỉ dùng **EICAR**, sinh lúc container start từ nhiều mảnh chuỗi. Không commit chuỗi EICAR nguyên vẹn hay file test nhị phân.
- **Không truy cập host/URL lấy từ threat feed.** Chỉ kiểm tra bằng dryrun (spec §12.3) hoặc phân tích offline.
- Trang phishing mẫu chỉ dùng thương hiệu hư cấu **“UIT Bank”**, với `form action="#"`. Không mô phỏng thương hiệu có thật.
- Không commit: private key, htpasswd, `.env`, `CLAUDE.local.md`, feed đã tải, log, pcap, `*.keys`, `results/`.
- Không đưa secret hay credential thật vào code, log hay tài liệu. Mật khẩu ở §6 là mật khẩu lab, được phép.

## 8. Quy ước

- **Ngôn ngữ:** trả lời người dùng bằng **tiếng Việt**. Tài liệu trong `docs/` viết tiếng Việt, giữ thuật ngữ kỹ thuật tiếng Anh. Comment trong code viết **tiếng Anh**, ngắn.
- **Bash:** `#!/usr/bin/env bash`, `set -euo pipefail`, qua `shellcheck`.
- **Python:** ≥ 3.10, chỉ dùng stdlib, có type hints, không `pip install`.
- **Squid conf:** mỗi file `conf.d` lo đúng một việc. Comment dẫn mục spec, ví dụ `# spec §5.4`.
- **Git:**
  - Nhánh: `<track>/<TASK-ID>-<slug>`.
  - Commit: Conventional Commits có task ID, ví dụ `feat(squid): POL-3 add http_access order`.
  - Mô tả PR theo plan §4.1.
- **Khi context dài hoặc vừa bị compact:** đọc lại file này, `docs/progress.md` và mục spec của task. Kiểm tra trạng thái bằng lệnh thật. Không suy đoán phần đã làm.
