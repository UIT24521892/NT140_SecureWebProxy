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

Máy đã cài đủ công cụ và Docker đang chạy thì chỉ cần:

```bash
make init
make up
make ps
```

Máy mới thì làm theo mục [Chạy lab từ đầu](#chạy-lab-từ-đầu).

## Chạy lab từ đầu

Làm lần lượt 4 bước:

1. [Cài môi trường](#bước-1-cài-môi-trường): chọn 1 trong 4 cách.
2. [Kiểm tra công cụ](#bước-2-kiểm-tra-công-cụ).
3. [Clone và khởi động lab](#bước-3-clone-và-khởi-động-lab).
4. [Xác nhận lab chạy đúng](#bước-4-xác-nhận-lab-chạy-đúng).

Tài nguyên cấp cho Docker tối thiểu: **4 vCPU, 6 GB RAM, 40 GB disk** (spec §1).

### Bước 1: Cài môi trường

| Cách | Khi nào dùng | Kiến trúc |
|---|---|---|
| [A. macOS + Docker Desktop](#a-macos--docker-desktop) | Mac, môi trường của TV1 | arm64 trên Mac M2 |
| [B. Windows + Docker Desktop](#b-windows--docker-desktop-wsl2) | Laptop Windows, cách dễ nhất cho TV2, TV3 | amd64 |
| [C. Linux hoặc Linux VM + Docker Engine](#c-linux-hoặc-linux-vm--docker-engine) | Máy Linux sẵn, hoặc muốn dùng VM | amd64 hoặc arm64 |
| [D. Windows + Docker Engine trong WSL2](#d-windows--docker-engine-trong-wsl2) | Máy Windows yếu, không chạy nổi Docker Desktop | amd64 |

#### A. macOS + Docker Desktop

1. Cài công cụ dòng lệnh của Apple (có `git`, `make`):
   ```bash
   xcode-select --install
   ```
2. Tải [Docker Desktop cho Mac](https://docs.docker.com/desktop/setup/install/mac-install/). Mac M1/M2 chọn bản **Apple silicon**.
3. Mở Docker Desktop, vào **Settings → Resources**, đặt Memory ≥ 6 GB và CPU ≥ 4.
4. Mở Docker bằng lệnh sau nếu chưa mở, rồi đợi đến khi `docker info` chạy không báo lỗi:
   ```bash
   open -a Docker
   docker info
   ```

#### B. Windows + Docker Desktop (WSL2)

Trên Windows, **mọi lệnh của lab đều chạy trong shell Ubuntu (WSL)**, không chạy trong PowerShell hay CMD. Chỉ các lệnh `wsl` trong mục này mới chạy trong PowerShell.

1. Mở PowerShell bằng quyền Administrator. Xem tên bản Ubuntu 24.04 trong danh sách, rồi cài theo đúng tên đó và khởi động lại máy:
   ```powershell
   wsl --list --online
   wsl --install -d Ubuntu-24.04
   ```
2. Mở Ubuntu từ Start menu và tạo user Linux khi được hỏi.
3. Kiểm tra trong PowerShell: cột `VERSION` phải là `2`, và WSL phải từ bản 2.1.5 trở lên (chạy `wsl --update` nếu cũ hơn).
   ```powershell
   wsl --list --verbose
   wsl --version
   ```
4. Nếu trong Ubuntu đã từng cài Docker Engine hoặc Docker CLI thì **gỡ trước**, vì chạy song song sẽ xung đột. Sau đó cài [Docker Desktop cho Windows](https://docs.docker.com/desktop/setup/install/windows-install/).
5. Mở Docker Desktop, kiểm tra hai thiết lập rồi bấm **Apply** ([tài liệu](https://docs.docker.com/desktop/features/wsl/)):
   - **Settings → General**: bật **Use WSL 2 based engine**. Trên một số máy, mục này bật sẵn và không hiển thị.
   - **Settings → Resources → WSL Integration**: bật cho bản Ubuntu vừa cài.
6. Cấp tài nguyên. WSL mặc định dùng 50% RAM của Windows. Nếu con số này dưới 6 GB, hoặc CPU cần giới hạn, tạo file `%UserProfile%\.wslconfig` ([tài liệu](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)):
   ```ini
   [wsl2]
   memory=8GB
   processors=4
   ```
   Sau đó chạy `wsl --shutdown` trong PowerShell rồi mở lại Ubuntu và Docker Desktop.
7. Trong shell Ubuntu, cài công cụ:
   ```bash
   sudo apt update
   sudo apt -y install git make curl openssl python3
   ```

#### C. Linux hoặc Linux VM + Docker Engine

1. Nếu dùng VM, tạo VM Ubuntu Server 24.04 theo [plan.md](plan.md) §3.1 (arm64) hoặc §3.2 (amd64). Máy chạy Linux sẵn thì bỏ qua bước này.
2. Cài Docker Engine và công cụ bằng khối lệnh trong [plan.md](plan.md) §3.3 (theo [tài liệu Docker](https://docs.docker.com/engine/install/ubuntu/)).
3. Lệnh `usermod` trong khối đó chỉ có hiệu lực sau khi **đăng xuất rồi đăng nhập lại**.
4. Muốn dùng lab từ laptop (demo, Wireshark) thì xem [plan.md](plan.md) §3.4.

#### D. Windows + Docker Engine trong WSL2

Cách này không dùng Docker Desktop. Nếu máy đã có Docker Desktop, hãy dùng cách B để tránh xung đột.

1. Làm bước 1–3 của cách B để có Ubuntu 24.04 trên WSL 2.
2. Làm bước 6 của cách B để cấp tài nguyên.
3. Docker Engine cần systemd. Trong shell Ubuntu, chạy `systemctl status`. Nếu lệnh báo lỗi, thêm đoạn sau vào `/etc/wsl.conf` rồi chạy `wsl --shutdown` trong PowerShell và mở lại Ubuntu ([tài liệu](https://learn.microsoft.com/en-us/windows/wsl/systemd)):
   ```ini
   [boot]
   systemd=true
   ```
4. Cài Docker Engine và công cụ bằng khối lệnh trong [plan.md](plan.md) §3.3, sau đó đóng rồi mở lại shell Ubuntu.

### Bước 2: Kiểm tra công cụ

```bash
uname -m
git --version
make --version | head -1
openssl version
python3 --version
docker compose version
docker run --rm hello-world
```

| Mục | Yêu cầu |
|---|---|
| `uname -m` | `arm64` hoặc `aarch64` (TV1), `x86_64` (TV2, TV3) |
| `python3` | ≥ 3.10. Trên Mac, nếu bản có sẵn cũ hơn thì chạy `brew install python` |
| `docker compose` | Compose v2, ≥ 2.20 |
| `hello-world` | In ra `Hello from Docker!` |

### Bước 3: Clone và khởi động lab

Trên Windows (cách B, D), **clone bằng `git` trong shell Ubuntu, vào thư mục home `~`**. Không clone vào `/mnt/c/...` và không dùng Git for Windows, vì script có thể bị đổi xuống dòng thành CRLF hoặc mất quyền thực thi.

Cần có quyền truy cập repo. Nếu `git clone` hỏi đăng nhập, xem cách thiết lập SSH key hoặc `gh auth login` ở [plan.md](plan.md) §3.3.

```bash
cd ~
git clone https://github.com/UIT24521892/NT140_SecureWebProxy.git project_nt140
cd project_nt140
make init
make up
make ps
```

- `make init` tạo `.env`, feed rỗng, `work_hours.conf` và chứng chỉ trong `certs/`. Chạy lại nhiều lần vẫn an toàn vì file đã có sẽ được giữ nguyên. Các file này không được commit.
- `make up` build image rồi đợi các service sẵn sàng. Lần đầu sẽ lâu hơn vì phải tải image.

Kết quả `make ps` đúng là có đủ **4 service**:

| Service | Cột `STATUS` |
|---|---|
| `squid` | `Up ... (healthy)` |
| `testweb` | `Up ... (healthy)` |
| `client-staff` | `Up ...` (không có healthcheck nên không hiện `healthy`) |
| `client-guest` | `Up ...` (không có healthcheck nên không hiện `healthy`) |

`icap`, `clamav`, `goaccess`, `sniffer`, `tcpecho` không xuất hiện là bình thường vì chúng thuộc profile chưa bật.

### Bước 4: Xác nhận lab chạy đúng

Hiện chưa có test runner nên phải kiểm tra bằng tay (`make test` chưa dùng được, xem [Lỗi thường gặp](#lỗi-thường-gặp)). Các lệnh dưới đây chạy tại thư mục gốc repo, trên bash và zsh đều được.

Các kiểm tra xác thực bên dưới cần code POL-1. Nếu `main` chưa ghép POL-1, chuyển sang nhánh đang review rồi build lại trước khi kiểm tra:

```bash
git switch pol/POL-1-auth
make up
```

**Squid và cô lập mạng:**

```bash
docker compose exec squid squid -k parse
docker compose exec squid squid -v | grep -c -- --with-openssl
docker compose exec squid curl -s -o /dev/null -w 'squid den testweb: %{http_code}\n' http://allowed.lab.test/
docker compose exec client-staff ip route
docker compose exec client-staff curl -sS --max-time 5 -o /dev/null http://allowed.lab.test/; echo "staff di thang: exit=$?"
docker compose exec client-guest curl -sS --max-time 5 -o /dev/null http://allowed.lab.test/; echo "guest di thang: exit=$?"
```

| Kiểm tra | Kết quả đúng |
|---|---|
| `squid -k parse` | Không có dòng `ERROR` hoặc `FATAL` |
| `squid -v` | In ra `1` |
| Squid đến testweb | `200` |
| `ip route` | Chỉ có dòng `10.10.0.0/24 ...`, **không có** dòng `default` |
| Client đi thẳng, không qua proxy | Lỗi `Could not resolve host`, `exit=6` (hoặc `exit=7`). Đây là kết quả mong đợi: client không có đường ra ngoài |

**Xác thực qua proxy:**

```bash
STAFF=http://10.10.0.10:3128
GUEST=http://10.20.0.10:3128
URL=http://allowed.lab.test/
docker compose exec client-staff curl -s -o /dev/null -w 'staff khong dang nhap: %{http_code}\n' -x $STAFF $URL
docker compose exec client-staff curl -s -o /dev/null -w 'staff sai mat khau: %{http_code}\n' -x $STAFF -U alice:sai $URL
docker compose exec client-staff curl -s -o /dev/null -w 'alice: %{http_code}\n' -x $STAFF -U alice:alice123 $URL
docker compose exec client-staff curl -s -o /dev/null -w 'bob: %{http_code}\n' -x $STAFF -U bob:bob123 $URL
docker compose exec client-staff curl -s -o /dev/null -w 'admin1: %{http_code}\n' -x $STAFF -U admin1:admin123 $URL
docker compose exec client-guest curl -s -o /dev/null -w 'guest khong dang nhap: %{http_code}\n' -x $GUEST $URL
```

Kết quả đúng: staff không đăng nhập và sai mật khẩu ra `407`; `alice`, `bob`, `admin1` và guest ra `200`.

**HTTPS qua proxy:**

```bash
STAFF=http://10.10.0.10:3128
GUEST=http://10.20.0.10:3128
docker compose exec client-staff curl -s -o /dev/null -w 'staff khong dang nhap: http=%{http_code} proxy=%{http_connect}\n' -x $STAFF https://allowed.lab.test/; echo "exit=$?"
docker compose exec client-staff curl -s -o /dev/null -w 'alice: %{http_code}\n' -x $STAFF -U alice:alice123 https://allowed.lab.test/
docker compose exec client-guest curl -s -o /dev/null -w 'guest: %{http_code}\n' -x $GUEST https://allowed.lab.test/
docker compose exec client-staff curl -sv -o /dev/null -x $STAFF -U alice:alice123 https://allowed.lab.test/ 2>&1 | grep -i issuer
```

Kết quả đúng ở giai đoạn hiện tại (TLS-3 chưa xong nên chưa giải mã HTTPS):

- Staff không đăng nhập ra `http=000 proxy=407` và `exit=56`. Đây **không phải lỗi**: proxy đã từ chối CONNECT bằng 407.
- `alice` và guest ra `200`.
- Issuer có `CN=NT140 Lab Public Root CA`.

**Log ghi đúng người dùng:**

```bash
docker compose exec squid tail -n 5 /var/log/squid/access.log
```

Nếu chạy theo đúng thứ tự trên, 5 dòng cuối là của khối HTTPS:

- Yêu cầu của `alice` có chữ `alice` trước `HIER_DIRECT`, ví dụ `TCP_TUNNEL/200 2432 CONNECT allowed.lab.test:443 alice HIER_DIRECT/172.30.0.50 -`.
- Yêu cầu của guest và yêu cầu bị từ chối có dấu `-` ở vị trí đó, ví dụ `TCP_DENIED/407 3474 CONNECT allowed.lab.test:443 - HIER_NONE/- text/html`.

Với yêu cầu HTTP, mã có thể là `TCP_MISS/200` hoặc `TCP_REFRESH_MODIFIED/200`, đều đúng.

Khi các chính sách chặn (POL-3) và SslBump (TLS-3) được ghép vào, một số kết quả trên sẽ đổi. Chuẩn cuối cùng vẫn là spec §13.

## Dùng hằng ngày

| Việc | Lệnh | Ghi chú |
|---|---|---|
| Xem danh sách lệnh | `make help` | Lệnh của task chưa làm sẽ báo `not implemented yet` |
| Xem trạng thái | `make ps` | |
| Xem log | `make logs SVC=squid` | Bấm Ctrl+C để thoát |
| Vào shell container | `make shell-staff`, `make shell-guest`, `make shell-squid` | Gõ `exit` để thoát |
| Nạp lại cấu hình Squid | `make reconfigure` | Không cần khởi động lại container |
| Tắt lab | `make down` | Giữ nguyên volume |
| Bật lại lab | `make up` | |
| Cập nhật code | `git pull`, rồi `make init`, rồi `make up` | `make up` tự build lại phần đã đổi |
| Kiểm tra script | `make lint` | Dùng `shellcheck` trên máy, nếu không có thì chạy bằng image Docker |
| Xóa sạch dữ liệu lab | `make clean` | **Mất volume, `logs/` và `results/`**, có hỏi xác nhận trước |

Cần nhớ:

- **Lab tự chạy lại khi mở Docker:** các service dùng `restart: unless-stopped`. Nếu tắt máy mà chưa `make down`, lab sẽ tự lên cùng Docker, nhưng vẫn là image và container cũ. Sau khi đổi code phải chạy `make up`.
- **Mỗi máy chỉ chạy được một lab:** tên Compose và subnet là cố định. Muốn chạy từ thư mục khác thì chạy `make down` ở thư mục cũ trước.
- **Không đổi `PUBLISH_ADDR` trong `.env`:** giá trị mặc định `127.0.0.1` chỉ cho máy này truy cập vào proxy. Chỉ dùng `0.0.0.0` khi demo với máy Kali/UTM (plan §3).

## Lỗi thường gặp

| Thông báo | Nguyên nhân | Cách xử lý |
|---|---|---|
| `failed to connect to the docker API ... docker.sock` hoặc `Cannot connect to the Docker daemon` | Docker chưa chạy | Mac, Windows: mở Docker Desktop và đợi khởi động xong. Linux, cách D: `sudo systemctl start docker` |
| `permission denied ... docker.sock` | User chưa thuộc nhóm `docker` | `sudo usermod -aG docker "$USER"`, rồi đăng xuất và đăng nhập lại |
| `docker: command not found` hoặc `could not be found in this WSL 2 distro` trong Ubuntu (cách B) | Chưa bật WSL Integration | Bật ở **Settings → Resources → WSL Integration**, rồi mở lại shell Ubuntu |
| `'compose' is not a docker command` hoặc `unknown flag: --wait` | Thiếu Compose v2 hoặc bản quá cũ | Cập nhật Docker lên bản có Compose ≥ 2.20 |
| `make: command not found` | Chưa cài `make` | Mac: `xcode-select --install`. Ubuntu: `sudo apt -y install make` |
| `Pool overlaps with other one on this address space` | Subnet `10.10.0.0/24`, `10.20.0.0/24`, `10.30.0.0/24` hoặc `172.30.0.0/24` bị project khác hay VPN chiếm | Tìm bằng `docker network ls`, tắt project đó hoặc tắt VPN. Không đổi subnet của lab |
| `Bind for 127.0.0.1:3128 failed: port is already allocated` | Có chương trình hoặc container khác đang dùng cổng 3128 | Tìm bằng `docker ps`, và `lsof -nP -iTCP:3128 -sTCP:LISTEN` (Mac) hoặc `ss -ltnp \| grep 3128` (Linux), rồi tắt chương trình đó |
| `squid` không lên, `make up` báo lỗi | Cấu hình hoặc file thiếu | Xem nguyên nhân bằng `docker compose logs squid` |
| `missing .../work_hours.conf, run 'make init' on the host` (trong log `squid`) | Chưa chạy `make init` | Chạy `make init`, rồi `make up` |
| `/usr/bin/env: 'bash\r': No such file or directory` | Script bị đổi sang CRLF, thường do clone bằng Git for Windows | Clone lại trong shell Ubuntu theo Bước 3 |
| `scripts/init.sh: Permission denied` | Clone vào `/mnt/c/...` nên mất quyền thực thi | Clone lại vào `~` theo Bước 3 |
| `not implemented yet (THR-2)` khi chạy `make test` | Chưa có test runner, không phải lỗi | Kiểm tra bằng tay theo Bước 4 |
| `407` hoặc `exit=6` trong Bước 4 | Thường là kết quả mong đợi | Đối chiếu với bảng kết quả đúng ở Bước 4 |
