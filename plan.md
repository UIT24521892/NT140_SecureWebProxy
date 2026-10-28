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

Hệ thống được kiểm chứng bằng **11 kịch bản nghiệp vụ (S1–S11), kèm kiểm tra khởi động S0, hơn 80 trường hợp kiểm thử tự động**, có đo hiệu năng và phân tích giới hạn của HTTPS.

**Sản phẩm nộp:**
1. Repo GitHub (code, config, script, kết quả test).
2. Báo cáo (Word/PDF).
3. Slide.
4. Video demo (khoảng 10 phút).
5. Thư mục `results/` của lần chạy cuối, chạy trên cả arm64 và amd64.

---

## 2. Nhóm, vai trò và phạm vi sở hữu

**Cách đọc:** đọc phần giải thích công việc từng người ở §2.2–§2.5 và lịch từng tuần ở §5 trước. Bảng file ở §2.1 và mã công việc ở §6 dùng khi bắt tay sửa code hoặc tạo Issue trên GitHub.

Trong tài liệu này, “track” nghĩa là mảng công việc; “milestone” là mốc nghiệm thu chung; “bàn giao” nghĩa là có cấu hình/code, hướng dẫn chạy và bằng chứng kiểm thử để người khác dùng được.

> Tên thành viên điền vào cột “Người”. Giả định TV2 và TV3 dùng laptop x86_64 (Windows hoặc Linux). Nếu khác thì chỉ cần sửa mục §3.

| | Người | Máy / Lab VM | Track | Trách nhiệm chính |
|---|---|---|---|---|
| **TV1** | _(điền)_ | **MacBook M2, Docker Desktop, arm64** | **INF/POL**: hạ tầng và chính sách | Trưởng nhóm, repo, compose, image squid, auth/ACL/http_access, trang chặn, giờ làm, cache, băng thông. **Gác cổng arm64** |
| **TV2** | _(điền)_ | x86, Docker Desktop hoặc Linux/VM, amd64 | **TLS**: website thử nghiệm, HTTPS và chống vượt proxy | PKI, client, testweb, probe, SslBump 3 mode, chống bypass, Wireshark, benchmark, phân tích giới hạn TLS |
| **TV3** | _(điền)_ | x86, Docker Desktop hoặc Linux/VM, amd64 | **THR**: bảo vệ trước mối đe dọa và giám sát | test runner, logformat, ICAP/ClamAV, threat feed/UT1, đánh giá FP, log summary, dashboard |

### 2.1 Phạm vi sở hữu file

Quy tắc: chỉ sửa file thuộc track của mình. Nếu cần sửa file của track khác thì mở PR nhỏ và tag người sở hữu vào review.

| Track | File / thư mục sở hữu |
|---|---|
| INF/POL (TV1) | `docker-compose.yml` (khung chung và block `squid`), `Makefile`, `.env.example`, `.gitignore`, `README.md`<br>`docker/squid/Dockerfile`, `docker/squid/entrypoint.sh`<br>`docker/squid/conf/squid.conf`, `conf.d/{00,10,11,12,13,40,41,50,70}-*.conf`<br>`templates/delay.conf.tmpl`, `docker/squid/errors/`<br>`policy/**`, `scripts/set-worktime.sh`<br>`tests/scenarios/{s01,s02,s06,s10}_*.py`<br>`docs/{architecture,policy-matrix,demo-runbook}.md` |
| TLS (TV2) | `scripts/gen-certs.sh`, `certs/README.md`<br>`docker/client/**`, `docker/testweb/**`, `tests/probe/**`<br>`docker/squid/templates/sslbump-*.conf.tmpl`, phần khởi tạo `ssl_db` trong entrypoint (phối hợp với TV1)<br>`scripts/{set-tls-mode,capture,bench}.sh`, `scripts/bench.py`<br>block compose `client-*`, `testweb`, `sniffer`, `tcpecho`<br>`tests/scenarios/{s07,s08,s09}_*.py`<br>`docs/{tls-limitations,wireshark}.md` |
| THR (TV3) | `docker/icap/**`, block compose `icap`, `clamav`, `goaccess`<br>`docker/squid/templates/icap.conf.tmpl`, `conf.d/14-dryrun.conf`, `conf.d/60-logging.conf`<br>`scripts/set-icap.sh`, `scripts/{update_feeds,log_summary,eval_fp,eval_feed_freshness,eval_coverage}.py`<br>`tests/run_all.py`, `tests/lib/**`, `tests/scenarios/{s00,s03,s04,s05,s11}_*.py`<br>`docs/scenarios.md`, `docs/report/outline.md` |
| Chung | `spec.md`, `plan.md`, `CLAUDE.md`. Sửa qua PR và cần **2 người duyệt**.<br>`docs/progress.md`: mỗi track chỉ sửa section của mình.<br>`docs/verify-log.md`, `docs/open-questions.md`: chỉ được thêm dòng mới, không sửa dòng cũ. |

**Phối hợp testweb (TLS-9, TV2 phụ trách):** TV2 dựng và bảo trì nginx, host alias, endpoint, file thử và MIME theo spec §8, đồng thời cung cấp chứng chỉ qua TLS-1. TV1 phụ trách mạng và kết nối từ Squid tới testweb; TV3 kiểm tra dữ liệu thử phục vụ antivirus/phishing và viết test cho phần THR. Nếu cần thêm hoặc sửa endpoint, TV1/TV3 phối hợp với TV2.

### 2.2 Thành viên 1 — Dựng hệ thống và đặt luật truy cập web

**Mục tiêu:** dựng được proxy làm cửa đi ra web của lab, rồi quyết định ai được truy cập nội dung nào và vào thời điểm nào.

1. **Dựng bộ khung lab.** Chuẩn bị repo, lệnh chạy chung, các mạng Docker, địa chỉ IP và nơi lưu cấu hình/log. Dựng container Squid để hai máy client có thể gửi yêu cầu truy cập web qua proxy.
2. **Làm đăng nhập và phân quyền.** Tạo tài khoản nhân viên, quản trị viên và cách nhận diện máy khách. Cấu hình để nhân viên phải đăng nhập, khách dùng chính sách mạng khách, quản trị viên được áp dụng quyền riêng theo spec.
3. **Viết luật cho phép/chặn.** Cấu hình danh sách kiểm soát truy cập (ACL) theo mạng, người dùng, nhóm website, địa chỉ IP, đường dẫn và loại file. Đặt đúng thứ tự xét luật; tạo trang thông báo để người dùng biết vì sao bị chặn. TV3 cung cấp danh sách domain từ các nguồn bên ngoài; TV1 cấu hình cách áp dụng chúng trong chính sách.
4. **Áp dụng giờ làm việc.** Ví dụ: nhân viên bị chặn mạng xã hội trong giờ làm nhưng được truy cập ngoài giờ. Làm công cụ chuyển giữa giờ thật, giả lập trong giờ và giả lập ngoài giờ để demo không phụ thuộc đồng hồ.
5. **Làm cache và giới hạn tốc độ.** Cho phép lưu lại nội dung phù hợp để lần tải sau nhanh hơn; giới hạn băng thông khách. Chứng minh bằng log cache và số đo tốc độ, không chỉ bằng cảm giác khi tải.
6. **Kiểm thử và tích hợp.** Viết test cho chính sách theo mạng, tài khoản/giờ làm, chặn loại file, cache và băng thông. Chạy thay đổi của TV2/TV3 trên Mac arm64; phối hợp người sở hữu tính năng để sửa lỗi tích hợp.
7. **Làm tài liệu và tổ chức demo.** Vẽ kiến trúc, lập bảng quyền truy cập, viết trình tự demo, ghép slide và video. Viết các phần báo cáo về tổng quan, thiết kế, triển khai hạ tầng/chính sách và kết luận.

**Bàn giao:** lab khởi động được; tài khoản và luật truy cập hoạt động đúng; trang chặn có lý do; có kết quả test chính sách/cache/băng thông; có sơ đồ kiến trúc, bảng chính sách và hướng dẫn demo.

**Ví dụ phải trình diễn được:** Alice đăng nhập đúng thì mở được website sạch; vào mạng xã hội trong giờ làm thì bị chặn với lý do phù hợp; máy khách tải file bị giới hạn tốc độ.

### 2.3 Thành viên 2 — Dựng website thử nghiệm, xử lý HTTPS và kiểm tra vượt proxy

**Mục tiêu:** cung cấp các website/file để cả nhóm thử nghiệm, đồng thời chứng minh proxy kiểm soát được gì khi lưu lượng web có mã hóa HTTPS.

1. **Dựng testweb bằng nginx.** Tạo các tên miền giả lập cho website sạch, mạng xã hội, ngân hàng hư cấu, phishing, tải file và kiểm thử cache. Chuẩn bị đường dẫn, nội dung, kích thước file, kiểu nội dung trả về (MIME) và file EICAR theo spec §8. EICAR là dữ liệu kiểm thử antivirus, không dùng malware thật. Website này phục vụ lab, không cần làm giao diện sản phẩm hoàn chỉnh.
2. **Tạo chứng chỉ và cấu hình máy client.** Tạo CA (tổ chức cấp chứng chỉ) cho website giả lập và CA riêng cho proxy. Máy nhân viên tin CA của proxy; máy khách không tin CA này. Cài chứng chỉ phù hợp trong từng container client.
3. **Làm công cụ gửi yêu cầu kiểm thử.** Viết probe chạy trong client: gửi request rồi trả kết quả theo định dạng JSON thống nhất, phân biệt truy cập thành công, bị chặn, lỗi đăng nhập, lỗi chứng chỉ và các lỗi kết nối theo spec. TV3 dùng kết quả đó trong bộ chạy test chung.
4. **Cấu hình ba cách xử lý HTTPS.** Chế độ chuyển tiếp nguyên kết nối mã hóa (splice); chế độ giải mã để kiểm tra rồi mã hóa lại (bump); chế độ chọn lọc (selective), giải mã máy được quản lý nhưng giữ nguyên kết nối của khách và website thuộc danh sách ngoại lệ. Viết lệnh chuyển chế độ và kiểm tra chứng chỉ client nhìn thấy.
5. **Kiểm tra giới hạn và cách vượt proxy.** Thử truy cập thẳng không qua proxy, dùng IP, cổng khác, DNS qua HTTPS (DoH) và UDP mô phỏng QUIC. Phối hợp TV1 về luật truy cập. Chứng minh cả các giới hạn như ứng dụng ghim khóa/chứng chỉ (pinning) có thể lỗi khi proxy giải mã.
6. **Bắt gói và đo hiệu năng.** Lưu gói tin để xem bằng Wireshark; so sánh HTTP, HTTPS chuyển tiếp và HTTPS giải mã. Đo thời gian phản hồi, CPU/RAM giữa truy cập trực tiếp, qua proxy, có/không cache và có/không quét antivirus. Nhờ TV1 chạy lại phần đo trên arm64.
7. **Viết test và báo cáo phần mình.** Viết test HTTPS và chống vượt proxy; lưu ảnh Wireshark, bảng đo và nhận xét. Viết tài liệu về giới hạn TLS, phần triển khai testweb/client/chứng chỉ, slide và thuyết minh phần HTTPS.

**Bàn giao:** testweb đủ dữ liệu cho cả nhóm; client và chứng chỉ hoạt động; probe trả kết quả đúng định dạng; chuyển được ba chế độ HTTPS; có test chống vượt proxy, gói tin mẫu, bảng đo hiệu năng và giải thích giới hạn.

**Ví dụ phải trình diễn được:** cùng một URL HTTPS, ở chế độ splice proxy không đọc được đường dẫn bên trong; khi giải mã trên máy nhân viên, proxy có thể kiểm tra đường dẫn và chuyển nội dung tải xuống cho antivirus. Máy khách có thể gặp lỗi chứng chỉ nếu ép giải mã toàn bộ.

### 2.4 Thành viên 3 — Quét nội dung độc hại, cập nhật danh sách chặn và tổng hợp bằng chứng

**Mục tiêu:** phát hiện website/file có dấu hiệu nguy hiểm và tạo bằng chứng tự động cho biết hệ thống đã xử lý từng yêu cầu như thế nào.

1. **Làm bộ chạy test chung.** Viết chương trình gọi probe của TV2, chuẩn bị trạng thái lab, chạy các trường hợp kiểm thử, so sánh kết quả mong đợi và xuất bảng kết quả Markdown/CSV. Làm bản kiểm tra khởi động tối thiểu trước để TV1/TV2 có thể dùng sớm.
2. **Chuẩn hóa log.** Cấu hình Squid ghi các trường cần thiết như người dùng, URL, trạng thái, lý do chặn và chế độ HTTPS. Gắn mã của từng lượt test để đối chiếu kết quả với dòng log tương ứng; kiểm tra log không chứa mật khẩu.
3. **Nối antivirus vào proxy.** Dựng ClamAV và c-icap. c-icap nhận nội dung phản hồi từ Squid và chuyển sang ClamAV để quét. Làm trang thông báo phát hiện virus; kiểm tra file sạch, EICAR, file mã hóa và hành vi khi dịch vụ quét bị lỗi theo spec.
4. **Cập nhật danh sách website.** Viết công cụ tải, chuẩn hóa và lưu danh sách phishing, malware và nhóm nội dung từ các nguồn quy định trong spec. Phối hợp TV1 để Squid dùng danh sách đó; kiểm thử bằng cơ chế giả lập, không truy cập thật vào URL nguy hiểm trong feed.
5. **Viết test phần bảo vệ và giám sát.** Kiểm tra chặn phishing/domain độc hại, quét file tải xuống, lọc theo nhóm website và tính đầy đủ của log. Dữ liệu website/file do TV2 dựng; TV3 kiểm tra dữ liệu có đáp ứng tình huống cần thử hay không và đề nghị TV2 sửa nếu thiếu.
6. **Tổng hợp và đánh giá.** Viết script thống kê log, dựng dashboard GoAccess, đo tỷ lệ chặn nhầm trên danh sách domain phổ biến theo phương pháp của spec. Phân biệt số liệu đã đo với nhận xét về giới hạn của phương pháp.
7. **Biên tập phần kết quả của nhóm.** Viết phần lý thuyết/triển khai antivirus, feed và logging. Nhận kết quả và nhận xét do TV1/TV2 viết cho phần của họ, rồi ghép thành chương đánh giá và tài liệu kịch bản; làm slide và thuyết minh phần mình.

**Bàn giao:** bộ chạy test sinh được bảng kết quả; log đối chiếu được từng test; ClamAV chặn được EICAR ở lưu lượng có thể quét; danh sách chặn cập nhật được; có báo cáo thống kê log, dashboard và đánh giá chặn nhầm.

**Ví dụ phải trình diễn được:** file sạch được tải về, EICAR bị chặn và có log chứng minh; HTTPS không giải mã thì antivirus không đọc được file bên trong; domain phishing có trong danh sách bị chặn nhưng domain chưa có trong danh sách có thể lọt qua.

### 2.5 Cách ba người phối hợp và xác định công việc đã xong

| Bên bàn giao | Người nhận | Thứ cần bàn giao |
|---|---|---|
| TV1 | TV2, TV3 | Khung Compose, mạng/IP, Squid chạy được và các lệnh khởi động lab |
| TV2 | TV1, TV3 | Website/file thử nghiệm đúng spec, chứng chỉ/client và probe trả JSON |
| TV3 | TV1, TV2 | Khung chạy test, cách thêm test và cách tìm bằng chứng trong log |
| TV2 | TV3 | Chế độ giải mã HTTPS để antivirus có thể quét nội dung HTTPS |
| TV3 | TV1 | File danh sách domain đã chuẩn hóa để áp dụng chính sách |
| Mỗi người | TV3 | Kết quả test, ảnh/bằng chứng và nhận xét hoàn chỉnh của phần mình để ghép báo cáo |

**Mỗi người tự viết và sửa test cho tính năng mình phụ trách.** TV3 bảo trì bộ chạy test chung và tổng hợp kết quả. Khi lỗi nằm trong tính năng của ai, người đó xử lý; không giao toàn bộ lỗi test cho TV3 hoặc lỗi tích hợp cho TV1.

**Kiểm tra trên hai loại CPU:** TV1 chạy trên arm64; TV2 và TV3 chia nhau chạy trên amd64. Người kiểm tra gửi output cho người sở hữu tính năng cùng xử lý nếu có khác biệt.

Một việc chỉ được coi là xong khi người khác chạy lại được theo hướng dẫn, có kết quả kiểm thử thật và đã cập nhật tiến độ. Các phần mở rộng như LDAP, proxy trong suốt và so sánh công cụ khác chỉ làm khi chức năng chính đã ổn định.

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

## 5. Lộ trình theo tuần và điều kiện hoàn thành từng mốc

> Giữ lịch dự kiến từ **22/10/2026 đến 20/12/2026**. Đây là lịch mục tiêu, không phải xác nhận việc đã xong; trạng thái thực tế xem `docs/progress.md`.
>
> **Ưu tiên bắt buộc (P0):** lab chạy được, chính sách cơ bản, HTTPS, antivirus, chặn domain độc hại và log kiểm chứng. **Ưu tiên tiếp theo (P1):** lọc category từ nguồn ngoài, chặn loại file, chống vượt proxy, cache/băng thông và công cụ đánh giá theo spec. **Mở rộng (P2):** chỉ làm khi các phần trước đã ổn định. Một kịch bản có thể gồm test ở nhiều mức ưu tiên; khi nghiệm thu phải theo mức của từng test trong spec.

### 5.1 Tuần 0 — Chuẩn bị môi trường và thống nhất cách làm (22–25/10)

- **TV1:** tạo repo và cây thư mục, lệnh chạy chung, cấu hình mẫu và tài liệu khởi động. Chuẩn bị Docker Desktop trên Mac M2; thống nhất tên dịch vụ, mạng và IP theo spec.
- **TV2:** chuẩn bị Docker trên máy amd64; đọc phần kiến trúc, chứng chỉ, website thử nghiệm, client và HTTPS. Xác định các domain, đường dẫn và file mà testweb cần cung cấp.
- **TV3:** chuẩn bị Docker trên máy amd64; đọc phần antivirus, log, danh sách chặn và test runner. Thống nhất với TV2 định dạng kết quả probe, dữ liệu EICAR và cách liên kết request với log.

**Mốc M0 — Cả nhóm sẵn sàng phát triển:** cả ba người clone được repo, chạy được container kiểm tra `hello-world` và biết lệnh làm việc chung. Có thể dùng Docker Desktop hoặc Docker Engine trên Linux/VM theo §3; không bắt buộc tự tạo ba máy ảo.

### 5.2 Tuần 1 — Dựng lab và kiểm tra truy cập cơ bản (26/10–01/11)

- **TV1:** dựng các mạng Docker, container Squid, nơi lưu log/cache và cơ chế kiểm tra dịch vụ. Cho hai client đi qua proxy tới website thử nghiệm; kiểm tra khung lab trên arm64.
- **TV2:** tạo chứng chỉ, cấu hình client nhân viên/khách, hoàn thiện testweb với HTTP/HTTPS và các file/đường dẫn theo spec. Viết probe để gửi request và trả kết quả JSON cho bộ test; kiểm tra trên amd64.
- **TV3:** làm bộ chạy test tối thiểu, kiểm tra các dịch vụ cơ bản và xuất bảng kết quả. Chuẩn hóa log để có thể tìm đúng request của từng lượt test. Có thể dùng kết quả probe giả lập trong lúc TV2 chưa xong, sau đó phải ghép với probe thật.

**Mốc M1 — Khung lab chạy được:** khởi động được Squid, testweb và hai client; hai client truy cập HTTP/HTTPS qua Squid; phần kiểm tra khởi động cho các dịch vụ này tự động đạt trên cả arm64 lẫn amd64 và sinh file kết quả. Kiểm tra khởi động antivirus được nghiệm thu cùng luồng quét ở mốc chức năng chính, sau khi c-icap/ClamAV đã được triển khai.

### 5.3 Tuần 2 — Làm chính sách, HTTPS và bắt đầu quét file (02–08/11)

- **TV1:** làm đăng nhập, nhóm quyền và danh sách ACL; viết thứ tự luật cho phép/chặn theo mạng, tài khoản và domain. Tạo trang chặn có lý do, kiểm tra các quyền nhân viên/khách/admin theo ma trận chính sách.
- **TV2:** triển khai ba chế độ HTTPS: chuyển tiếp nguyên kết nối mã hóa, giải mã toàn bộ và giải mã chọn lọc. Làm lệnh chuyển chế độ; kiểm tra máy nhân viên tin CA proxy và máy khách không tin CA này.
- **TV3:** dựng ClamAV và c-icap, nối luồng quét nội dung từ Squid. Phối hợp TV2 dùng file sạch/EICAR trên testweb; bắt đầu test quét file HTTP và xử lý khi dịch vụ quét lỗi.

**Điều kiện chuyển sang tuần sau:** luật cơ bản chạy được, chuyển được chế độ HTTPS, và luồng quét có thể xử lý file thử. Các phần còn lỗi phải được ghi rõ để ưu tiên sửa trước buổi demo nội bộ.

### 5.4 Tuần 3 — Ghép chức năng chính và demo nội bộ (09–15/11)

- **TV1:** hoàn thiện chính sách giờ làm và công cụ giả lập trong/ngoài giờ. Viết test chính sách theo mạng, tài khoản và thời gian; kiểm tra thay đổi ghép từ TV2/TV3 trên arm64.
- **TV2:** hoàn thiện test HTTPS chuyển tiếp/giải mã: xác minh chứng chỉ, khả năng thấy đường dẫn, ngoại lệ không giải mã và lỗi pinning/máy chưa tin CA. Hỗ trợ TV1 kiểm tra các chính sách liên quan tới HTTPS.
- **TV3:** hoàn thiện test antivirus, bao gồm HTTPS có/không giải mã và hành vi khi dịch vụ quét bị lỗi. Kiểm tra chặn domain phishing/malware bằng danh sách cục bộ; kiểm tra log có lý do chặn và không lộ mật khẩu. Làm bản thống kê log tối thiểu phục vụ kiểm thử bắt buộc; dashboard hoàn thiện ở tuần 5.

**Mốc M2 — Có bản chức năng chính để demo:** toàn bộ test bắt buộc đạt trên cả hai kiến trúc, bao gồm đầy đủ kiểm tra khởi động c-icap/ClamAV. Cả nhóm trình diễn được đăng nhập/phân quyền, chặn domain, khác biệt giữa HTTPS giải mã và không giải mã, chặn EICAR và đối chiếu log. Các test cố ý chứng minh giới hạn phải cho đúng kết quả mà spec quy định.

### 5.5 Tuần 4 — Bổ sung kiểm soát và danh sách chặn bên ngoài (16–22/11)

- **TV1:** làm cache và giới hạn băng thông khách. Hoàn thiện kiểm thử chặn loại file theo URL/kiểu nội dung, cache lần tải sau và chênh lệch tốc độ giữa khách với nhân viên.
- **TV2:** kiểm thử cách vượt proxy qua kết nối trực tiếp, IP, cổng khác, DoH và UDP mô phỏng QUIC. Hoàn thiện cấu hình liên quan, phối hợp TV1 về luật chặn; bắt gói mẫu cho HTTP, HTTPS chuyển tiếp, HTTPS giải mã và luồng quét file.
- **TV3:** làm công cụ cập nhật danh sách phishing/malware và nhóm nội dung từ các nguồn bên ngoài. Kiểm tra chuẩn hóa, lưu bản tải và áp dụng lại cấu hình; viết test lọc category và domain từ feed mà không truy cập thật vào website nguy hiểm.

**Điều kiện hoàn thành tuần:** có số đo cache/băng thông, kết quả thử vượt proxy, gói tin mẫu và kết quả dùng danh sách bên ngoài. Nếu nguồn feed không tải được, ghi lỗi và lý do bỏ qua theo spec; vẫn phải kiểm thử danh sách cục bộ.

### 5.6 Tuần 5 — Đo hiệu năng và đánh giá kết quả (23–29/11)

- **TV1:** hoàn thiện sơ đồ kiến trúc, bảng chính sách và hướng dẫn demo. Chạy lại test sau khi ghép tính năng; chạy bộ đo của TV2 trên arm64 và gửi kết quả, xử lý lỗi thuộc hạ tầng/chính sách.
- **TV2:** chạy đủ các cấu hình đo truy cập trực tiếp/qua proxy, HTTP/HTTPS, có/không cache và có/không quét antivirus trên amd64. Tổng hợp thời gian phản hồi, CPU/RAM của cả hai kiến trúc; viết nhận xét và bản nháp tài liệu giới hạn HTTPS.
- **TV3:** hoàn thiện script thống kê log và dashboard; đánh giá tỷ lệ chặn nhầm theo spec. Thu kết quả test phần bảo vệ, bảng thống kê, nhận xét và các giới hạn đã quan sát được.

**Mốc M3 — Có số liệu đánh giá:** test ưu tiên tiếp theo đạt, hoặc được bỏ qua kèm lý do mà spec cho phép. Có bảng đo hiệu năng trên hai kiến trúc, báo cáo thống kê log, dashboard và báo cáo chặn nhầm. Kết quả phải do công cụ sinh từ lần chạy thật.

### 5.7 Tuần 6 — Sửa lỗi, chốt tính năng và lưu kết quả cuối (30/11–06/12)

- **TV1:** ưu tiên sửa lỗi tích hợp và chính sách, kiểm tra từ bản clone sạch trên arm64. Chỉ thử LDAP nếu phần chính đã ổn định và không làm trễ việc chốt bài.
- **TV2:** sửa lỗi HTTPS/testweb/client, bổ sung ảnh Wireshark và hướng dẫn đọc gói tin. Chạy lại phần mình trên amd64; proxy trong suốt và tunnel không phải TLS là phần mở rộng, chỉ làm nếu còn thời gian.
- **TV3:** sửa lỗi antivirus/feed/test runner, tập hợp kết quả các kịch bản và khung báo cáo. Chỉ thử cảnh báo file mã hóa hoặc so sánh công cụ lọc khác nếu đủ thời gian.
- **Cả nhóm:** chạy lại bộ test sau các bản sửa cuối, lưu kết quả riêng cho arm64/amd64 và ghi rõ cấu hình, thời điểm, giới hạn còn tồn tại. Mỗi người hoàn thiện bằng chứng và nhận xét phần mình.

**Mốc M4 — Chốt bản dùng để nộp:** ngừng thêm tính năng mới; bản cuối dựng lại được, có kết quả test trên hai kiến trúc và đủ dữ liệu để viết báo cáo/demo. Nếu tiến độ trễ, bỏ toàn bộ phần mở rộng và dành tuần này để sửa lỗi, hoàn thiện tài liệu.

### 5.8 Tuần 7 — Viết báo cáo và làm slide (07–13/12)

- **TV1:** viết tổng quan, cơ sở về proxy/SWG, thiết kế hệ thống, triển khai hạ tầng/chính sách và kết luận. Viết kết quả kịch bản của mình, ghép slide và thống nhất hình thức.
- **TV2:** viết cơ sở HTTP/TLS/chứng chỉ, triển khai testweb/client/HTTPS, kết quả test HTTPS/chống vượt proxy, phân tích hiệu năng và giới hạn. Làm slide phần mình.
- **TV3:** viết cơ sở và triển khai antivirus/feed/logging, kết quả test phần bảo vệ, thống kê và chặn nhầm. Nhận nội dung đánh giá hoàn chỉnh của TV1/TV2 rồi ghép chương kịch bản và đánh giá. Làm slide phần mình.
- **Cả nhóm:** đọc chéo, kiểm tra hình/bảng có nguồn từ kết quả thật và lời giải thích thống nhất với cấu hình cuối.

**Mốc M5 — Có bản nháp đầy đủ:** báo cáo và slide đã đủ nội dung, hình minh họa, bảng kết quả và nhận xét để cả nhóm rà soát.

### 5.9 Tuần 8 — Tập demo, quay video và nộp bài (14–20/12)

- **TV1:** chạy demo theo hướng dẫn đã viết, ghép video khoảng 10 phút, kiểm tra repo và bộ tài liệu nộp.
- **TV2:** thuyết minh website thử nghiệm/HTTPS, giải thích gói tin và kết quả đo; hỗ trợ xử lý sự cố client/chứng chỉ khi tập demo.
- **TV3:** thuyết minh antivirus, danh sách chặn, log và đánh giá; rà soát bảng kết quả và giới hạn được trình bày.
- **Cả nhóm:** tập câu hỏi bảo vệ, rà soát báo cáo/slide/video và kiểm tra cách bàn giao kết quả theo yêu cầu môn học. Giữ kết quả thô trong gói nộp riêng theo quy định; không đưa dữ liệu đã gitignore lên repo ngoài ý muốn.

**Mốc M6 — Sẵn sàng nộp:** đủ repo, báo cáo, slide, video và kết quả cuối; các thành viên hiểu và giải thích được cả luồng hoạt động chung lẫn phần mình thực hiện.

### 5.10 Việc nào cần chờ nhau, việc nào có thể làm trước?

- **Bắt đầu ngay sau khi có repo:** TV2 làm chứng chỉ, testweb, client và probe; TV3 thiết kế bộ test, dữ liệu đầu vào/đầu ra và bộ đọc log. Có thể chuẩn bị trước theo spec trong lúc TV1 dựng Squid.
- **Muốn kiểm tra quyền truy cập thực tế:** cần Squid và các luật của TV1, client/testweb của TV2, bộ test của TV3. Trước khi ghép đủ, mỗi người kiểm tra riêng phần mình và lưu bằng chứng.
- **Muốn quét file HTTPS:** cần cả chế độ giải mã của TV2 và luồng c-icap/ClamAV của TV3. HTTPS chuyển tiếp nguyên kết nối mã hóa sẽ không cung cấp nội dung file cho antivirus.
- **Muốn đo và viết kết luận:** phải có cấu hình đủ ổn định, dữ liệu thử cố định và kết quả từ hai kiến trúc. Bắt đầu viết mô tả thiết kế sớm, bổ sung số liệu sau khi đo thật.
- **Ưu tiên khi chậm tiến độ:** môi trường và Squid → chính sách/HTTPS/antivirus → test bắt buộc → tính năng ưu tiên tiếp theo và đánh giá → báo cáo/demo. Phần mở rộng được bỏ trước.

---

## 6. Bảng công việc kỹ thuật để tra cứu khi triển khai

Mã như `TLS-9` hay `THR-4` chỉ là nhãn để tạo Issue, đặt tên nhánh và liên kết PR. Nội dung công việc của từng người đã được giải thích ở §2; lịch thực hiện bằng chữ nằm ở §5. `INF` là hạ tầng, `POL` là chính sách, `TLS` là mảng của TV2, `THR` là mảng bảo vệ/giám sát của TV3, `DOC` là tài liệu. Riêng testweb thuộc TV2 và mang mã `TLS-9`.

Cột “DoD” là điều kiện để coi task là xong. Ngoài điều kiện riêng ghi trong bảng, **mọi task** đều phải:
- qua được `shellcheck` và `python3 -m py_compile` cho file đã sửa;
- chạy `squid -k parse` sạch, nếu có sửa cấu hình squid;
- đã cập nhật `docs/progress.md`.

### 6.1 TV1 — Hạ tầng và chính sách (INF/POL)

| ID | Việc | Spec | Phụ thuộc | DoD |
|---|---|---|---|---|
| INF-1 | Tạo khung repo: `git init`, tạo repo GitHub, `.gitignore`, `.editorconfig`, `README.md` khung, `Makefile` có đủ target (target chưa làm thì in “not implemented”), `.env.example`, cây thư mục, stub `docs/{verify-log,open-questions}.md` | §15 | — | `make help` liệt kê đủ target. Repo đã được push và đủ 3 người clone được |
| INF-2 | `docker-compose.yml`: 4 network, IP tĩnh, **stub cho mọi service** (để track khác chỉ cần sửa block của mình), healthcheck, `depends_on`, publish 127.0.0.1 | §2.1–2.2 | INF-1 | `docker compose config` hợp lệ |
| INF-3 | Image squid: gói `squid-openssl`, lưu bản `squid.conf.documented`, entrypoint (render envsubst, `squid -z`, `-k parse`, chạy foreground), conf.d khung, placeholder `20-sslbump.conf` với `http_port 3128`, tạm cho phép cả hai LAN | §2.1, §6.1, §15 | INF-2 | T0.1, T0.2, T0.5 PASS trên arm64 và amd64 |
| POL-1 | Auth: sinh htpasswd và file nhóm từ `users.lab`, cấu hình `auth_param` | §4 | INF-3 | T1.8, T2.1, T2.2 PASS |
| POL-2 | Seed list local, định nghĩa đủ ACL ở §5.2 (đúng tên), `make init` tạo feed rỗng | §5.1–5.2 | INF-3 | `squid -k parse` sạch khi feed rỗng |
| POL-3 | `http_access` / `http_reply_access` đúng thứ tự §5.4, ACL `mark_*`, `deny_info`, template `ERR_LAB_*` có marker | §5.3–5.4, §5.6 | POL-1, POL-2 | T1.1–T1.6 PASS. Trang chặn hiển thị đúng lý do |
| POL-4 | `scripts/set-worktime.sh` với 3 mode, `make worktime` | §5.5 | POL-3 | T2.4–T2.8 PASS |
| POL-5 | Cache và delay pool | §5.7–5.8 | POL-3, TLS-9 | S10 PASS |
| POL-6 | Viết module test `s01`, `s02`, `s06`, `s10` | §13 | THR-2 | S1, S2, S6, S10 PASS |
| DOC-1 | `docs/architecture.md` (Mermaid), `policy-matrix.md`, `demo-runbook.md` | §16 | POL-3 | Đã được 1 người review |
| INF-5 | *(Stretch)* OpenLDAP, giữ nguyên tên `grp_*` | §4, §14 | POL-6 | S2 vẫn PASS |
| INF-6 | *(Tùy chọn)* GitHub Actions: shellcheck, py_compile, build image squid, `squid -k parse` | — | INF-3 | CI xanh |

### 6.2 TV2 — Website thử nghiệm, HTTPS và chống vượt proxy (TLS)

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
| TLS-9 | Image testweb: đủ host alias và path, sinh file lúc start, EICAR ghép từ mảnh, MIME đúng như spec | §2.3, §8 | INF-2, TLS-1 | Từ container squid `curl` được mọi path. `git grep` không thấy chuỗi EICAR nguyên vẹn |

### 6.3 TV3 — Bảo vệ, kiểm thử chung và giám sát (THR)

| ID | Việc | Spec | Phụ thuộc | DoD |
|---|---|---|---|---|
| THR-2 | `tests/run_all.py`, `tests/lib/` (model Case, quản lý state, lấy evidence từ log, ghi CSV/MD), `s00_smoke.py`; tuần 1 kiểm tra phần khung, bổ sung kiểm tra antivirus khi có THR-4 | §11, §13 S0 | TLS-2; THR-4 để chạy đủ S0 (có thể mock probe trước) | `make test S=S0` sinh `results/latest/results.md`; đủ S0 đạt trước M2 |
| THR-3 | `60-logging.conf` (logformat `lab`, TSV, 16 trường), parser log dùng chung trong `tests/lib` | §10.1 | INF-3 | Runner tìm được dòng log theo `X-Lab-Test-Id` |
| THR-4 | Service clamav (kiểm tra arm64, có fallback), image icap (`virus_scan` + `clamd_mod`), `icap.conf.tmpl`, `set-icap.sh`, template VIRUS_FOUND, module `s05` | §7, §13 S5 | INF-3, TLS-9 | S5 PASS (gồm cả các case `[L]` và fail-closed/fail-open) trên 2 kiến trúc |
| THR-5 | `update_feeds.py` (URLhaus, OpenPhish, UT1, chuẩn hóa, snapshot, thống kê), `14-dryrun.conf`, module `s03` | §12, §13 S3 | POL-2, THR-2 | `make feeds` ra file không rỗng. S3, T4.5, T4.6 PASS |
| THR-6 | Module `s04`, `s11`; dùng bản thống kê log tối thiểu của THR-7 để kiểm tra audit | §13 S4, S11 | POL-3, THR-3 | S4 (phần local), S11 PASS |
| THR-7 | `log_summary.py` (bản tối thiểu trước mốc chức năng chính), service goaccess và thống kê đầy đủ trước mốc đánh giá | §10.2–10.3 | THR-3 | `make summary` chạy được. Dashboard mở được tại `127.0.0.1:7890` |
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
| 4. Triển khai: 4.1 hạ tầng và policy · 4.2 testweb, client và TLS · 4.3 ICAP, feed, logging | TV1 · TV2 · TV3 |
| 5. Kịch bản và đánh giá (mỗi người viết kết quả/nhận xét phần mình; TV2 chủ trì số đo hiệu năng; TV3 biên tập chung) | Cả nhóm, TV3 chủ trì |
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
| TLS (TV2) | TLS 1.2 và 1.3 handshake, X.509 và chuỗi tin cậy, tạo CA bằng `openssl`, **SNI**, **ECH**, HSTS, certificate pinning, Certificate Transparency<br>**SslBump**: `at_step`, peek/stare/splice/bump/terminate, `security_file_certgen`<br>QUIC/HTTP3, DoH/DoT<br>iptables/nftables REDIRECT/TPROXY (stretch)<br>Wireshark: display filter, giải mã bằng SSLKEYLOGFILE<br>nginx: virtual host, HTTPS, MIME, Cache-Control và sinh dữ liệu testweb |
| THR (TV3) | **ICAP** (RFC 3507, REQMOD/RESPMOD), c-icap và module `virus_scan`/`clamd_mod`<br>ClamAV (clamd, freshclam, signature, các giới hạn kích thước và file mã hóa), file EICAR<br>Phishing (typosquatting, homoglyph), threat feed (URLhaus, OpenPhish), blacklist UT1, Tranco list<br>Phân tích log bằng Python, GoAccess<br>Đo FP/FN |

### 9.3 Tài liệu tham khảo

- **Squid:**
  - squid-cache.org/Doc/config (tra từng directive);
  - Squid Wiki: *Features/SslPeekAndSplice*, *Features/SslBump*, *ConfigExamples*, *Features/ICAP*.
- **RFC:** RFC 9110 (HTTP Semantics), RFC 8446 (TLS 1.3), RFC 3507 (ICAP), RFC 6761 (tên miền dành riêng, `.test`).
- **c-icap / ClamAV:** c-icap.sourceforge.net; tài liệu ClamAV (docs.clamav.net); eicar.org.
- **Bài báo:** Durumeric et al., *“The Security Impact of HTTPS Interception”*, NDSS 2017. Dùng cho chương 6.
- **Bối cảnh ngành:** tài liệu mô tả SWG và SSE của các hãng (Zscaler, Netskope, Cloudflare Gateway). Chỉ dùng cho chương 2.1.
