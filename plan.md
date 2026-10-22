# PLAN: Secure Web Gateway Lab (NT140, Đề tài 03), nhóm 3 người

> `spec.md` quy định **làm cái gì**: kiến trúc, cấu hình, test. Đây là nguồn sự thật.
> `plan.md` quy định **ai làm, khi nào, theo thứ tự nào**.
> Nếu hai file mâu thuẫn thì theo `spec.md`.
> `CLAUDE.md` là quy tắc cho Claude Code.
> `docs/progress.md` ghi trạng thái hiện tại.

---

## 1. Mục tiêu và sản phẩm

Dựng một Secure Web Gateway gồm:
- Squid 6 làm forward proxy, kèm SslBump.
- c-icap + ClamAV để quét file tải xuống.
- Chính sách theo user/network/domain/thời gian.
- URL filtering bằng threat feed và blacklist UT1.
- Cache, giới hạn băng thông, log và dashboard.

Hệ thống được kiểm chứng bằng **11 kịch bản (S0–S11), hơn 80 test case tự động**, có đo hiệu năng và phân tích giới hạn của HTTPS.

**Sản phẩm nộp:**
1. Repo GitHub (code, config, script, kết quả test).
2. Báo cáo (Word/PDF).
3. Slide.
4. Video demo (khoảng 10 phút).
5. Thư mục `results/` của lần chạy cuối, chạy trên cả arm64 và amd64.

---

## 2. Nhóm, vai trò và phạm vi sở hữu

> Tên thành viên điền vào cột “Người”. Giả định TV2 và TV3 dùng laptop x86_64 (Windows hoặc Linux). Nếu khác thì chỉ cần sửa mục §3.

| | Người | Máy / Lab VM | Track | Trách nhiệm chính |
|---|---|---|---|---|
| **TV1** | _(điền)_ | **MacBook M2, UTM, Ubuntu 24.04 arm64** | **INF/POL**: hạ tầng và chính sách | Trưởng nhóm, repo, compose, image squid, auth/ACL/http_access, trang chặn, giờ làm, cache, băng thông. **Gác cổng arm64** |
| **TV2** | _(điền)_ | x86, VMware/VirtualBox, Ubuntu 24.04 amd64 | **TLS**: HTTPS và chống bypass | PKI, client, probe, SslBump 3 mode, chống bypass, Wireshark, benchmark, phân tích giới hạn TLS |
| **TV3** | _(điền)_ | x86, VMware/VirtualBox, Ubuntu 24.04 amd64 | **THR**: bảo vệ trước mối đe dọa và giám sát | testweb, test runner, logformat, ICAP/ClamAV, threat feed/UT1, đánh giá FP, log summary, dashboard |

### 2.1 Phạm vi sở hữu file

Quy tắc: chỉ sửa file thuộc track của mình. Nếu cần sửa file của track khác thì mở PR nhỏ và tag người sở hữu vào review.

| Track | File / thư mục sở hữu |
|---|---|
| INF/POL (TV1) | `docker-compose.yml` (khung chung và block `squid`), `Makefile`, `.env.example`, `.gitignore`, `README.md`<br>`docker/squid/Dockerfile`, `docker/squid/entrypoint.sh`<br>`docker/squid/conf/squid.conf`, `conf.d/{00,10,11,12,13,40,41,50,70}-*.conf`<br>`templates/delay.conf.tmpl`, `docker/squid/errors/`<br>`policy/**`, `scripts/set-worktime.sh`<br>`tests/scenarios/{s01,s02,s06,s10}_*.py`<br>`docs/{architecture,policy-matrix,demo-runbook}.md` |
| TLS (TV2) | `scripts/gen-certs.sh`, `certs/README.md`<br>`docker/client/**`, `tests/probe/**`<br>`docker/squid/templates/sslbump-*.conf.tmpl`, phần khởi tạo `ssl_db` trong entrypoint (phối hợp với TV1)<br>`scripts/{set-tls-mode,capture,bench}.sh`, `scripts/bench.py`<br>block compose `client-*`, `sniffer`, `tcpecho`<br>`tests/scenarios/{s07,s08,s09}_*.py`<br>`docs/{tls-limitations,wireshark}.md` |
| THR (TV3) | `docker/testweb/**`, `docker/icap/**`, block compose `testweb`, `icap`, `clamav`, `goaccess`<br>`docker/squid/templates/icap.conf.tmpl`, `conf.d/14-dryrun.conf`, `conf.d/60-logging.conf`<br>`scripts/set-icap.sh`, `scripts/{update_feeds,log_summary,eval_fp,eval_feed_freshness,eval_coverage}.py`<br>`tests/run_all.py`, `tests/lib/**`, `tests/scenarios/{s00,s03,s04,s05,s11}_*.py`<br>`docs/scenarios.md`, `docs/report/outline.md` |
| Chung | `spec.md`, `plan.md`, `CLAUDE.md`. Sửa qua PR và cần **2 người duyệt**.<br>`docs/progress.md`: mỗi track chỉ sửa section của mình.<br>`docs/verify-log.md`, `docs/open-questions.md`: chỉ được thêm dòng mới, không sửa dòng cũ. |

---

## 3. Môi trường (spec §1)

Toàn bộ lab chạy bằng **Docker Compose**, nên mỗi người chỉ cần một máy có Docker:
- **TV1 (Mac M2, arm64):** dùng **Docker Desktop chạy thẳng trên macOS**. Đây là cách tiện nhất, không cần VM. Cấp cho Docker ≥ 6 GB RAM (Settings → Resources).
- **TV2, TV3 (x86, amd64):** dùng Docker Desktop (Windows/WSL2), hoặc một Linux VM theo §3.2–3.3.
- **Kali trên UTM (tùy chọn):** làm máy client/phân tích khi demo, có sẵn Wireshark và trình duyệt. Kali trỏ proxy tới `<IP máy Mac>:3128`. Muốn vậy thì phải publish port 3128 ra IP mạng Shared của UTM, không chỉ 127.0.0.1.

Hai kiến trúc arm64 (TV1) và amd64 (TV2/TV3) giúp các lỗi phụ thuộc kiến trúc lộ ra sớm.

Các mục §3.1–3.3 dưới đây là **phương án dùng VM**. Chỉ cần làm theo nếu không dùng Docker Desktop.

### 3.1 (Tùy chọn) Mac M2 + UTM, Linux VM arm64

1. Cài UTM (mac.getutm.app). Tải **Ubuntu Server 24.04.x LTS ARM64** ISO (ubuntu.com/download/server/arm).
2. Tạo VM theo các bước:
   - UTM → *Create a New Virtual Machine* → **Virtualize** (không chọn Emulate) → Linux → chọn ISO.
   - CPU **4 core**. RAM:
     - Mac 16 GB: cấp **8 GB**.
     - Mac 8 GB: cấp **6 GB**, và tắt bớt app khi chạy ClamAV.
   - Disk **≥ 48 GB**. Network: **Shared Network** (VM nhận IP dạng 192.168.64.x, Mac truy cập trực tiếp được).
3. Cài Ubuntu:
   - Chọn **Install OpenSSH server**.
   - **Không** chọn snap `docker` trong danh sách *Featured server snaps*.
   - Cài xong thì gỡ ISO khỏi ổ CD/DVD của VM rồi mới reboot.
4. Lấy IP bằng `ip -4 a`. Thêm vào `~/.ssh/config` trên Mac:
   ```
   Host labvm
     HostName 192.168.64.X
     User <user>
     LocalForward 3128 127.0.0.1:3128
     LocalForward 7890 127.0.0.1:7890
   ```
5. **Lưu ý riêng cho M2 / UTM:**
   - Sau khi Mac sleep, đồng hồ của VM có thể bị lệch. Đồng hồ lệch làm hỏng việc kiểm tra cert TLS và time ACL. Kiểm tra bằng `timedatectl`. Nếu lệch, chạy `sudo systemctl restart systemd-timesyncd`.
   - Không dùng `platform: linux/amd64` / QEMU user-mode để “chạy cho được”. Image nào không có arm64 thì ghi vào `docs/verify-log.md` và dùng phương án thay thế trong spec (ví dụ ClamAV build từ Ubuntu).
   - Giữ repo **trong ổ đĩa của VM**. Không đặt repo trong thư mục chia sẻ của UTM, vì chậm và dễ lỗi quyền file.

### 3.2 TV2, TV3: laptop x86_64 (amd64)

- **Khuyến nghị:** VMware Workstation Pro 17 (miễn phí cho cá nhân) hoặc VirtualBox 7. Tải **Ubuntu Server 24.04.x LTS amd64**. Cấu hình 4 vCPU, 8 GB RAM, ≥ 48 GB disk.
- **Network:**
  - VMware NAT: host truy cập thẳng IP của VM.
  - VirtualBox NAT: phải thêm port forward 2222→22, hoặc gắn thêm card **Host-only**.
- **Phương án thay thế khi máy yếu:** WSL2 Ubuntu 24.04 + Docker Engine cài bên trong WSL (không dùng Docker Desktop).
- Nếu laptop chạy Linux sẵn: dùng trực tiếp, không cần VM.
- Cài OpenSSH server và cấu hình `~/.ssh/config` giống mục 3.1.

### 3.3 Cài đặt chung trong Lab VM (cả 3 người)

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git make curl ca-certificates jq shellcheck python3 tcpdump
# Docker Engine theo repo chính thức
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt update && sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"   # đăng xuất rồi đăng nhập lại
docker run --rm hello-world && docker compose version && uname -m   # aarch64 (TV1) / x86_64 (TV2, TV3)
```

Sau khi cài xong:
- **Git:** tạo SSH key trong VM (`ssh-keygen -t ed25519`) và thêm key vào GitHub, hoặc dùng `gh auth login`. Clone repo vào `~/project_nt140`.
- **Soạn code:** dùng VS Code với extension **Remote - SSH**, kết nối tới `labvm` và mở thư mục repo.
- **Claude Code:** cài **bên trong VM**, vì đó là nơi có `docker` và `make`, nên Claude Code chạy được test thật. Cài theo hướng dẫn chính thức, ví dụ `curl -fsSL https://claude.ai/install.sh | bash`. Có thể dùng extension Claude Code trên VS Code Remote-SSH, hoặc CLI `claude` trong terminal SSH.
- **File cá nhân:** mỗi người tạo `CLAUDE.local.md` (đã gitignore), ví dụ:
  ```
  Tôi là TV2, track TLS, Lab VM amd64 (VMware). Mặc định chỉ sửa file thuộc track TLS (plan.md §2.1).
  ```

### 3.4 Dùng lab từ laptop (demo, Wireshark)

- **Trình duyệt:**
  - `ssh labvm` (đã có LocalForward), rồi trong Firefox đặt Manual proxy `127.0.0.1:3128` và tick “cũng dùng cho HTTPS”.
  - Import `certs/lab-public-ca.crt` và `certs/lab-proxy-ca.crt` vào Firefox (Settings → Certificates).
  - Request đi từ host được tính là “nguồn khác” nên phải đăng nhập (vd `alice` / `alice123`), xem spec §5.3.
- **Wireshark:**
  - Chạy `make capture NAME=s07-splice SECS=30` trong VM.
  - Chép file về laptop: `scp labvm:~/project_nt140/captures/s07-splice.* .`
  - Mở bằng Wireshark. File `.keys` dùng để giải mã TLS, cách làm ở `docs/wireshark.md`.

---

## 4. Quy trình làm việc nhóm

### 4.1 Git và review

- **Repo:** GitHub, **private**. Nhánh `main` được bảo vệ: chỉ merge qua PR, cần 1 người review, dùng squash merge.
- **Nhánh:** `<track>/<TASK-ID>-<slug>`, ví dụ `tls/TLS-3-sslbump-modes`.
- **Commit:** Conventional Commits, có ghi task ID, ví dụ `feat(squid): TLS-3 add selective bump template`.
- **Mỗi task ở §6 là 1 GitHub Issue.** Dùng board GitHub Projects với các cột Todo → In progress → Review → Done.
- **Mô tả PR phải có:**
  - task ID;
  - mục spec liên quan;
  - lệnh test đã chạy và **output thật** (rút gọn nếu dài);
  - dòng `Tested: arm64 ✅/❌  amd64 ✅/❌`;
  - thay đổi spec, nếu có (kèm dòng tương ứng trong `verify-log.md`).

### 4.2 Gác cổng hai kiến trúc

PR có sửa `docker/**`, `docker-compose.yml`, `Makefile`, `tests/lib/**`, `tests/probe/**` hoặc `tests/run_all.py` phải được chạy thử trên **kiến trúc còn lại** trước khi merge:
- PR của TV2 hoặc TV3: **TV1 chạy trên arm64**.
- PR của TV1: **TV2 hoặc TV3 chạy trên amd64**.

Lệnh tối thiểu: `make build && make up && make test P=P0`. Nếu PR chỉ ảnh hưởng một phần thì chạy thêm `make test S=<scenario liên quan>`.

### 4.3 Họp và theo dõi tiến độ

- **Họp:** 1 buổi/tuần, 30 phút (đề xuất tối Chủ nhật). Nội dung: demo phần đã merge, cập nhật milestone, gỡ blocker, nhận task tuần sau.
- **Cập nhật hằng ngày:** mỗi người cập nhật section track của mình trong `docs/progress.md` khi xong một phiên làm việc.
- **Blocker** liên quan tới track khác: ghi vào `docs/open-questions.md` và báo ngay trong nhóm chat.

### 4.4 Làm việc với Claude Code

Quy tắc chi tiết nằm trong `CLAUDE.md`. Phía người dùng cần làm:

1. **Mỗi phiên làm một task.** Câu mở đầu mẫu:
   > `Task THR-4. Đọc docs/progress.md, spec.md §7 và §13 S5. Trình bày kế hoạch ngắn, chờ tôi duyệt rồi mới làm.`
2. **Chuyển sang task khác:** dùng `/clear`. Nếu phiên đã dài: dùng `/compact` kèm ghi chú, ví dụ `/compact giữ lại: task THR-4, đã xong clamd, đang làm c-icap`.
3. **Kết thúc phiên:**
   > `Cập nhật section THR trong docs/progress.md: đã làm gì, lệnh test đã chạy và kết quả, việc tiếp theo.`
4. **Luôn tự đọc diff và output test thật** trước khi commit. Không để Claude push lên `main` hay tự merge PR.
5. Khi Claude dùng một directive hay option không có trong spec, yêu cầu nó **đưa ra bằng chứng**: trích từ `squid.conf.documented` hoặc output của `squid -k parse`.

---

## 5. Lộ trình và milestone

> Giả định bắt đầu từ **22/10/2026**, nộp bài trong khoảng **20/12/2026**. Nếu deadline sớm hơn: bỏ Stretch (W6), gộp W4 và W5, dùng W6 để viết báo cáo.

| Tuần | Thời gian | TV1 (INF/POL, arm64) | TV2 (TLS, amd64) | TV3 (THR, amd64) | Milestone |
|---|---|---|---|---|---|
| W0 | 22–25/10 | Lab VM UTM, **INF-1** (repo khung) | Lab VM, đọc spec §3, §6, §9 | Lab VM, đọc spec §7, §8, §10–§12 | **M0**: 3 VM chạy được `hello-world`, mọi người clone được repo, Claude Code chạy trong VM |
| W1 | 26/10–01/11 | INF-2, INF-3 | TLS-1, TLS-2 | THR-1, THR-2, THR-3 | **M1**: `make up` + **S0 PASS trên arm64 và amd64** |
| W2 | 02–08/11 | POL-1, POL-2, POL-3 | TLS-3 | THR-4 (bắt đầu) | — |
| W3 | 09–15/11 | POL-4, POL-6 (S1, S2) | TLS-4 (S7, S8) | THR-4 (S5), THR-6 (S4, S11) | **M2 (MVP)**: **toàn bộ P0 PASS trên 2 kiến trúc**, demo nội bộ |
| W4 | 16–22/11 | POL-5, POL-6 (S6, S10) | TLS-5 (S9), TLS-6 | THR-5 (S3, T4.5–4.6) | — |
| W5 | 23–29/11 | DOC-1, regression | TLS-7 (bench), DOC-2 (bản nháp) | THR-7, THR-8 | **M3**: P1 PASS, có kết quả bench, summary, eval-fp |
| W6 | 30/11–06/12 | Stretch INF-5 (tùy chọn), fix bug | Stretch TLS-8 (tùy chọn), capture ảnh | Stretch THR-9 (tùy chọn), DOC-3 | **M4**: chốt tính năng, regression cả 2 kiến trúc, lưu `results/` cuối |
| W7 | 07–13/12 | Báo cáo ch.1, 3, 4.1, 7 | Báo cáo ch.2.2, 4.2, 6 | Báo cáo ch.2.3, 4.3, 5 (tổng hợp) | **M5**: bản nháp báo cáo và slide |
| W8 | 14–20/12 | Chạy demo, ghép video | Slide phần TLS, tập demo | Slide phần đánh giá, rà soát | **M6**: nộp bài |

**Critical path:** INF-1 → INF-2 → INF-3 → {POL-*, TLS-3, THR-4}.

Các task TLS-1, TLS-2, THR-1, THR-2, THR-3 **không cần chờ** INF-3. Có thể bắt đầu ngay khi đã có repo, vì chúng làm việc dựa trên hợp đồng giao tiếp (tên, IP, định dạng JSON) đã cố định trong spec.

---

## 6. Danh sách task

Cột “DoD” là điều kiện để coi task là xong. Ngoài điều kiện riêng ghi trong bảng, **mọi task** đều phải:
- qua được `shellcheck` và `python3 -m py_compile` cho file đã sửa;
- chạy `squid -k parse` sạch, nếu có sửa cấu hình squid;
- đã cập nhật `docs/progress.md`.

### 6.1 Track INF/POL (TV1)

| ID | Việc | Spec | Phụ thuộc | DoD |
|---|---|---|---|---|
| INF-1 | Tạo khung repo: `git init`, tạo repo GitHub, `.gitignore`, `.editorconfig`, `README.md` khung, `Makefile` có đủ target (target chưa làm thì in “not implemented”), `.env.example`, cây thư mục, stub `docs/{verify-log,open-questions}.md` | §15 | — | `make help` liệt kê đủ target. Repo đã được push và đủ 3 người clone được |
| INF-2 | `docker-compose.yml`: 4 network, IP tĩnh, **stub cho mọi service** (để track khác chỉ cần sửa block của mình), healthcheck, `depends_on`, publish 127.0.0.1 | §2.1–2.2 | INF-1 | `docker compose config` hợp lệ |
| INF-3 | Image squid: gói `squid-openssl`, lưu bản `squid.conf.documented`, entrypoint (render envsubst, `squid -z`, `-k parse`, chạy foreground), conf.d khung, placeholder `20-sslbump.conf` với `http_port 3128`, tạm cho phép cả hai LAN | §2.1, §6.1, §15 | INF-2 | T0.1, T0.2, T0.5 PASS trên arm64 và amd64 |
| POL-1 | Auth: sinh htpasswd và file nhóm từ `users.lab`, cấu hình `auth_param` | §4 | INF-3 | T1.8, T2.1, T2.2 PASS |
| POL-2 | Seed list local, định nghĩa đủ ACL ở §5.2 (đúng tên), `make init` tạo feed rỗng | §5.1–5.2 | INF-3 | `squid -k parse` sạch khi feed rỗng |
| POL-3 | `http_access` / `http_reply_access` đúng thứ tự §5.4, ACL `mark_*`, `deny_info`, template `ERR_LAB_*` có marker | §5.3–5.4, §5.6 | POL-1, POL-2 | T1.1–T1.6 PASS. Trang chặn hiển thị đúng lý do |
| POL-4 | `scripts/set-worktime.sh` với 3 mode, `make worktime` | §5.5 | POL-3 | T2.4–T2.8 PASS |
| POL-5 | Cache và delay pool | §5.7–5.8 | POL-3, THR-1 | S10 PASS |
| POL-6 | Viết module test `s01`, `s02`, `s06`, `s10` | §13 | THR-2 | S1, S2, S6, S10 PASS |
| DOC-1 | `docs/architecture.md` (Mermaid), `policy-matrix.md`, `demo-runbook.md` | §16 | POL-3 | Đã được 1 người review |
| INF-5 | *(Stretch)* OpenLDAP, giữ nguyên tên `grp_*` | §4, §14 | POL-6 | S2 vẫn PASS |
| INF-6 | *(Tùy chọn)* GitHub Actions: shellcheck, py_compile, build image squid, `squid -k parse` | — | INF-3 | CI xanh |

### 6.2 Track TLS (TV2)

| ID | Việc | Spec | Phụ thuộc | DoD |
|---|---|---|---|---|
| TLS-1 | `scripts/gen-certs.sh` (idempotent, có `--force`), `certs/README.md`, sinh `pinned.sha256` | §3 | INF-1 | `openssl verify` qua với testweb cert. Proxy CA có CA:TRUE |
| TLS-2 | Image client: entrypoint cài CA theo `MANAGED`. `tests/probe/probe.sh` đúng hợp đồng JSON và đủ 6 outcome | §9, §9.1 | TLS-1 | Probe phân loại đúng cả 6 outcome. Kiểm tra bằng request thủ công và ghi lại trong PR |
| TLS-3 | 3 template `sslbump-*`, `set-tls-mode.sh`, khởi tạo `ssl_db`, terminate `threat_sni`, `on_unsupported_protocol` | §6 | INF-3, POL-2 | Chuyển qua lại được cả 3 mode, `squid -k parse` sạch ở mỗi mode |
| TLS-4 | Module `s07`, `s08`. Hỗ trợ TV1 với T1.5, T6.7, T6.8 | §6.3, §13 | TLS-3, THR-2 | S7, S8 PASS trên 2 kiến trúc |
| TLS-5 | Hardening chống bypass, module `s09` | §13 S9 | POL-3, TLS-4 | T9.1–T9.8 PASS |
| TLS-6 | Service `sniffer`, `capture.sh`, `tls_key_log`, `docs/wireshark.md`. Capture mẫu: HTTP, CONNECT splice, bump, ICAP | §10.4 | TLS-3 | Có ít nhất 4 pcap kèm ảnh chụp Wireshark trong docs |
| TLS-7 | `bench.sh` / `bench.py`, chạy đủ 8 cấu hình B1–B8 | §13.1 | TLS-4, THR-4 | Có `bench.md` cho cả arm64 và amd64 |
| DOC-2 | `docs/tls-limitations.md`: splice/bump, SNI, ECH, QUIC, DoH, pinning, HSTS, quyền riêng tư | §16 | TLS-5 | Đã được 1 người review |
| TLS-8 | *(Stretch)* Transparent intercept, container DNS, T9.9 với `tcpecho` | §14 | TLS-5 | Có tài liệu và test riêng |

### 6.3 Track THR (TV3)

| ID | Việc | Spec | Phụ thuộc | DoD |
|---|---|---|---|---|
| THR-1 | Image testweb: đủ host alias và path, sinh file lúc start, EICAR ghép từ mảnh, MIME đúng như spec | §2.3, §8 | INF-2, TLS-1 | Từ container squid `curl` được mọi path. `git grep` không thấy chuỗi EICAR nguyên vẹn |
| THR-2 | `tests/run_all.py`, `tests/lib/` (model Case, quản lý state, lấy evidence từ log, ghi CSV/MD), `s00_smoke.py` | §11, §13 S0 | TLS-2 (có thể mock probe trước) | `make test S=S0` sinh `results/latest/results.md` |
| THR-3 | `60-logging.conf` (logformat `lab`, TSV, 16 trường), parser log dùng chung trong `tests/lib` | §10.1 | INF-3 | Runner tìm được dòng log theo `X-Lab-Test-Id` |
| THR-4 | Service clamav (kiểm tra arm64, có fallback), image icap (`virus_scan` + `clamd_mod`), `icap.conf.tmpl`, `set-icap.sh`, template VIRUS_FOUND, module `s05` | §7, §13 S5 | INF-3, THR-1 | S5 PASS (gồm cả các case `[L]` và fail-closed/fail-open) trên 2 kiến trúc |
| THR-5 | `update_feeds.py` (URLhaus, OpenPhish, UT1, chuẩn hóa, snapshot, thống kê), `14-dryrun.conf`, module `s03` | §12, §13 S3 | POL-2, THR-2 | `make feeds` ra file không rỗng. S3, T4.5, T4.6 PASS |
| THR-6 | Module `s04`, `s11` | §13 S4, S11 | POL-3, THR-3 | S4 (phần local), S11 PASS |
| THR-7 | `log_summary.py`, service goaccess | §10.2–10.3 | THR-3 | `make summary` chạy được. Dashboard mở được tại `127.0.0.1:7890` |
| THR-8 | `eval_fp.py` (Tranco), *(P2)* `eval_feed_freshness.py`, `eval_coverage.py` | §12.4 | THR-5 | Có `eval_fp.md` |
| DOC-3 | `docs/scenarios.md` (tổng hợp S0–S11 từ `results/latest`), `docs/report/outline.md` | §16 | M3 | Đủ 11 scenario, mỗi scenario có nhận xét |
| THR-9 | *(Stretch)* Bật `AlertEncrypted yes` rồi đo lại T5.4; so sánh với ufdbGuard | §14 | THR-4 | Có ghi chú kết quả trong `scenarios.md` |

---

## 7. Rủi ro và phương án xử lý

| Rủi ro | Ảnh hưởng | Phương án |
|---|---|---|
| Image `clamav/clamav` không có arm64, hoặc RAM của M2 không đủ | S5 không chạy được trên Mac | Build ClamAV từ Ubuntu (`clamav-daemon`). Đặt `ConcurrentDatabaseReload no` để giảm đỉnh RAM. Nếu Mac chỉ có 8 GB: VM 6 GB, tắt app khác. Bất đắc dĩ thì TV1 kiểm S5 trên máy x86 và ghi rõ trong báo cáo |
| Directive của Squid 6 / c-icap khác với spec | Config lỗi, mất thời gian | Tra `squid.conf.documented` trong image và chạy `squid -k parse`, ghi `verify-log.md`, cập nhật spec trong cùng PR |
| Feed đổi URL hoặc yêu cầu API key | S3, T4.5, T4.6 bị SKIP | Seed local đã đủ cho các case P0. SKIP phải ghi rõ lý do. Có biến `ABUSECH_AUTH_KEY` |
| Xung đột merge ở compose hoặc conf.d | Chậm tiến độ | Phân quyền sở hữu theo §2.1, tạo stub sớm (INF-2), giữ PR nhỏ, rebase thường xuyên |
| Claude Code “ảo giác” (bịa directive, báo pass giả) hoặc mất context | Config sai, kết quả không đúng | Quy tắc trong `CLAUDE.md`, đọc `progress.md` mỗi phiên, review output thật, bắt buộc test 2 kiến trúc |
| Hành vi khác nhau giữa UTM và VMware (network, đồng hồ) | Test flaky | Chạy test trên cả 2 kiến trúc trước khi merge. Đồng bộ NTP. Ghi khác biệt vào `verify-log.md` |
| Thành viên trễ việc | Trễ milestone | Ưu tiên P0 trước P1. W6 là tuần dự phòng. Người rảnh nhận task từ backlog (cột Todo) |

---

## 8. Phân công báo cáo, slide và demo

| Chương | Người viết |
|---|---|
| 1. Tổng quan (bối cảnh, mục tiêu, phạm vi) | TV1 |
| 2.1 Proxy, SWG, so sánh với NGFW, DNS filtering, CASB, SASE/SSE | TV1 |
| 2.2 HTTP, CONNECT, TLS 1.2/1.3, PKI, SNI, ECH, HSTS, pinning | TV2 |
| 2.3 ICAP, antivirus dựa trên chữ ký, phishing, threat intelligence | TV3 |
| 3. Thiết kế (topology, ma trận chính sách, luồng request) | TV1 |
| 4. Triển khai: 4.1 hạ tầng và policy · 4.2 TLS · 4.3 ICAP, feed, logging | TV1 · TV2 · TV3 |
| 5. Kịch bản và đánh giá (mỗi người viết scenario của mình, TV3 tổng hợp) | Cả nhóm, TV3 chủ trì |
| 6. Giới hạn và thảo luận | TV2 |
| 7. Kết luận và hướng phát triển | TV1 |

- **Slide:** mỗi người làm phần của mình. TV1 ghép và thống nhất template.
- **Demo:** theo `docs/demo-runbook.md`. TV1 thao tác, TV2 và TV3 thuyết minh phần mình. Quay video ở W8.

---

## 9. Phụ lục: kiến thức cần học

> Dành cho thành viên nhóm. Claude Code có thể bỏ qua mục này.

### 9.1 Kiến thức chung (cả 3 người, W0–W1)

- **HTTP/1.1:**
  - method, status code;
  - header `Host`, `Proxy-Authorization`, `Via`, `X-Forwarded-For`, `Cache-Control`;
  - **CONNECT** (RFC 9110 §9.3.6).
- **Khái niệm proxy:**
  - forward, reverse, transparent;
  - explicit và intercept;
  - PAC/WPAD;
  - SWG khác NGFW và DNS filtering thế nào.
- **Squid căn bản:**
  - cấu trúc `squid.conf`;
  - kiểu ACL;
  - **`http_access` là first-match**;
  - đọc `access.log` (TCP_MISS, TCP_HIT, TCP_DENIED, TCP_TUNNEL).
- **Docker / Compose:** network (`internal`), volume, healthcheck, `exec`, build multi-arch.
- **Git:** branch, PR, rebase, xử lý conflict.

### 9.2 Theo track

| Track | Cần học |
|---|---|
| INF/POL (TV1) | Squid ACL nâng cao: `proxy_auth`, `time`, `external_acl_type`, `annotate_transaction`, `note`, `rep_mime_type`<br>`auth_param basic`, `deny_info` và error template<br>`refresh_pattern`, `cache_dir`, `delay_pools`<br>UTM và mạng ảo<br>*(Stretch)* LDAP |
| TLS (TV2) | TLS 1.2 và 1.3 handshake, X.509 và chuỗi tin cậy, tạo CA bằng `openssl`, **SNI**, **ECH**, HSTS, certificate pinning, Certificate Transparency<br>**SslBump**: `at_step`, peek/stare/splice/bump/terminate, `security_file_certgen`<br>QUIC/HTTP3, DoH/DoT<br>iptables/nftables REDIRECT/TPROXY (stretch)<br>Wireshark: display filter, giải mã bằng SSLKEYLOGFILE |
| THR (TV3) | **ICAP** (RFC 3507, REQMOD/RESPMOD), c-icap và module `virus_scan`/`clamd_mod`<br>ClamAV (clamd, freshclam, signature, các giới hạn kích thước và file mã hóa), file EICAR<br>Phishing (typosquatting, homoglyph), threat feed (URLhaus, OpenPhish), blacklist UT1, Tranco list<br>Phân tích log bằng Python, GoAccess<br>Đo FP/FN |

### 9.3 Tài liệu tham khảo

- **Squid:**
  - squid-cache.org/Doc/config (tra từng directive);
  - Squid Wiki: *Features/SslPeekAndSplice*, *Features/SslBump*, *ConfigExamples*, *Features/ICAP*.
- **RFC:** RFC 9110 (HTTP Semantics), RFC 8446 (TLS 1.3), RFC 3507 (ICAP), RFC 6761 (tên miền dành riêng, `.test`).
- **c-icap / ClamAV:** c-icap.sourceforge.net; tài liệu ClamAV (docs.clamav.net); eicar.org.
- **Bài báo:** Durumeric et al., *“The Security Impact of HTTPS Interception”*, NDSS 2017. Dùng cho chương 6.
- **Bối cảnh ngành:** tài liệu mô tả SWG và SSE của các hãng (Zscaler, Netskope, Cloudflare Gateway). Chỉ dùng cho chương 2.1.
