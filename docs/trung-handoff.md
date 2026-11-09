# Bàn giao TV2 — TLS

Phạm vi triển khai: TLS-1/2/3/4/5/6/7/9 và DOC-2. TLS-8 là phần mở rộng, chưa triển khai. Kết quả ngày 07/11 bên dưới được giữ nguyên; kết quả kiểm tra clone sạch được ghi riêng trong gói bằng chứng.

## Chạy và kiểm tra

Clone nhánh `tls/TLS-3-tv2-handoff` từ repo, rồi chạy tại gốc repo bằng Bash, Make, OpenSSL, Python >=3.10 và Docker Compose (macOS/Linux/WSL). Windows có thể dùng MSYS2 cho init/Make và Python Windows cho các entry point `.py`. Không sao chép `.env`, certs, log hoặc volume từ máy cũ; `make init` tái tạo trạng thái cục bộ.

Khi kiểm tra song song với lab khác, đặt `COMPOSE_PROJECT_NAME=nt140-tls-review` trước mọi lệnh Compose/script và dùng network `${COMPOSE_PROJECT_NAME}_wan` cho test testweb. Hai project vẫn dùng cùng subnet/cổng cố định; cần dừng project cũ bằng `docker compose down` (giữ volume) trước khi chạy clone.

```bash
make init
make build
make up
make tls-mode MODE=splice
make tls-mode MODE=bump
make tls-mode MODE=selective
docker compose exec -T client-staff bash /opt/lab/probe.sh -u alice:alice123 -t demo https://allowed.lab.test/
python3 scripts/test_tls.py --scenario S7
python3 scripts/test_tls.py --scenario S8
python3 scripts/test_tls.py --scenario S9
python3 scripts/test_tls.py --scenario SUPPORT
python3 scripts/test_tls.py --list
make bench N=50
```

Kết quả của bộ kiểm tra riêng TV2 ở `results/tls/<runid>/results.csv` và `results.md`. Bộ này trả exit 1 khi có FAIL, exit 2 khi không chạy được bước preflight. Nó phục hồi TLS mode và file giờ làm ban đầu sau khi chạy. `make test` toàn dự án vẫn thuộc THR-2; không được coi `test-tls` là bộ S0–S11 đã hoàn thiện.

Các entry point Python chạy được trên Windows nếu có Python và Docker CLI. `make` cho phép `PYTHON=/path/to/python`; các shell wrapper dùng Python3 trong PATH. Script shell trong Git bắt buộc LF theo `.gitattributes`.

## Tích hợp với TV1 và TV3

- PR TLS dựa trên `main` đã gộp THR-3, không gộp nhánh `pol/POL-1-auth`. Skeleton hiện chưa xác thực; truyền `alice:alice123` chỉ chuẩn bị cho hợp đồng actor, không chứng minh auth đã được nghiệm thu. Sau khi có POL-1 phải chạy lại các case actor/auth.
- TV1 tiếp tục sở hữu auth, ACL, `http_access`/`http_reply_access`, worktime, cache và delay pools. TV2 không thay luật đang ở dạng skeleton. Để S7/S8/S9 đạt đầy đủ, cần POL-2/3/5.
- TV3 có thể nạp `CASES` và `DEFAULT_STATE` từ `tests/scenarios/s07_splice.py`, `s08_selective.py`, `s09_bypass.py`. Đây là dictionary theo các trường Case trong spec; cần adapter sang model Case của THR-2 khi model đó được tạo.
- `SUPPORT_CASES` trong `s08_selective.py` cung cấp T1.5, T6.7, T6.8 để TV1 dùng khi ghép policy. Chạy riêng bằng `--scenario SUPPORT`.
- `scripts/test_tls.py` là công cụ nghiệm thu TV2 độc lập trong khi THR-2 chưa có. Không đổi expected thành ALLOW vì policy còn thiếu. Case T9.7 báo FAIL trước khi gửi ra ngoài nếu chưa có rule chặn DoH.
- TLS-3 thay phần render placeholder và thêm bước PKI/SSL DB trong entrypoint chung; Dockerfile Squid copy hai helper TLS. Makefile chỉ nối các target TV2. Đây là các thay đổi vào file chung cần TV1 review.
- `prepare-tls.sh` tạo `19-tls-acl.conf` cho những ACL TLS mà POL-2 chưa định nghĩa. Ưu tiên các khai báo sẵn trong conf.d; nguồn list dùng file đã có, nếu chưa có dùng seed domain lab trong spec. Khi POL-2 được ghép, helper tự nhường các khai báo đó.
- ICAP và cache không được thay bằng dịch vụ giả. B4/B8 không đo được trước THR-4; B3 cần POL-5. Benchmark ghi SKIP có lý do cho phần thiếu, không báo đã nghiệm thu đủ B1–B8.

## Header test ID và log splice

Với HTTP, curl `-H` đã gửi header tới proxy; thêm cùng tên bằng `--proxy-header` làm hai giá trị bị gộp. Probe chỉ thêm `--proxy-header` cho HTTPS CONNECT, đồng thời vẫn gửi `-H` cho request bên trong. Cả HTTP và HTTPS đều giữ mã test ở vị trí cần thiết. Đây là điều chỉnh cách gọi curl để đáp ứng mục tiêu liên kết log của spec §9.1.

Squid 6 có thể ghi hai dòng cho splice: dòng ban đầu chứa test ID với `NONE_NONE`, dòng cuối có `TCP_TUNNEL` nhưng không giữ request header. TV2 tạo thêm `access_tls.log`, gồm 16 trường lab cộng cổng nguồn client. `tls_support.log_record` đối chiếu chính xác IP+cổng của hai giai đoạn; giữ nguyên test ID rỗng của dòng gốc, ghi `matched_test_id` và `evidence_source` trong evidence. Không ghép theo hostname/thời gian gần đúng, không sửa parser/logformat 16 trường của THR-3.

## Unit/integration test bổ sung

```bash
docker run --rm --entrypoint python3 -v "$PWD:/work" -w /work nt140/client:dev -m unittest discover -s tests/tls -p 'test_p*.py' -v
docker run --rm --network nt140-swg_wan --entrypoint python3 -v "$PWD:/work:ro" -v "$PWD/certs:/opt/certs:ro" -w /work nt140/client:dev tests/tls/test_testweb.py
make lint
```

Test PKI dùng thư mục tạm, không xoay CA của lab đang chạy. Test probe dùng proxy HTTP cục bộ có phản hồi xác định, kiểm tra curl thật và JSON qua stdout. Test testweb chạy trên WAN, kiểm tra alias HTTPS, MIME, archive có mật khẩu, PDF và header cache. Không sinh EICAR ra filesystem Windows.

## Kết quả và phần còn chờ

Đã chạy thật trên **amd64**, Squid 6.14, ngày **2026-11-07**:

| Kiểm tra | Kết quả |
|---|---|
| Build/up, Compose config, parse ba mode | Đạt; hot-switch host trả exit 0, cuối cùng `TLS_MODE=selective` |
| Unit/integration PKI và probe | 9/9 đạt; gồm đủ sáu outcome và lỗi CONNECT 403 |
| Nginx testweb | 5/5 đạt; 13 alias HTTPS, MIME, ZIP/PDF, cache headers, HTML benchmark đúng 1024 byte |
| S7/S8/S9 | 18/25 đạt; 7 FAIL: T7.1, T7.2, T8.2, T8.7, T9.4, T9.6, T9.7 |
| Hỗ trợ TV1 | T6.7 đạt theo limitation; T1.5/T6.8 FAIL khi chưa có POL-3 |
| Benchmark | 500 mẫu; B1/B2/B5/B6/B7 đạt, mỗi payload 50 lượt; B3 SKIP do thiếu cache, B4/B8 SKIP do thiếu ICAP |
| Capture | `tv2-http`, `tv2-splice`, `tv2-bump`, `tv2-bump-tls12`: bốn pcap của ba loại lưu lượng, chưa có ICAP |
| Giải mã | tshark thấy `GET /` phía client bằng client TLS1.3 keys và `GET /capture/tv2-bump-tls12/` từ 172.30.0.10 bằng Squid keys/TLS1.2 |
| Lint | ShellCheck và Python syntax/compile đạt |
| Bộ P0 chung | `make test P=P0` dừng với `not implemented yet (THR-2)` |

Kết quả gốc (gitignored, phải giữ trong gói nộp riêng):
- [S7/S8/S9](../results/tls/20261107-203319-616b2e/results.md)
- [Ba case hỗ trợ](../results/tls/20261107-205119-786d79/results.md)
- [Benchmark](../results/bench/20261107-204741-89a07c/bench.md), kèm samples.csv, metadata.json và resources.json
- [Capture HTTP](../captures/tv2-http.pcap), [splice](../captures/tv2-splice.pcap), [bump](../captures/tv2-bump.pcap), [bump upstream TLS1.2](../captures/tv2-bump-tls12.pcap)

Các FAIL còn lại giữ nguyên expected của spec, với evidence gốc trong CSV/MD nêu trên:

| Case | Expected | Actual ngày 07/11 | Phần còn phụ thuộc |
|---|---|---|---|
| T7.1 | BLOCK:worktime | ALLOW | POL-2/3/4: phân loại social và giờ làm |
| T7.2 | BLOCK:path | ALLOW | POL-3: chặn HTTP path `/upload` |
| T8.2 | BLOCK:path | ALLOW | POL-3: chặn HTTPS path sau bump |
| T8.7 | Cache HIT=True | TCP_MISS cả hai lượt | POL-5: cache đối tượng 1 MB |
| T9.4 | BLOCK:ip-literal | ALLOW | POL-1/3: phân biệt actor và chặn IP literal |
| T9.6 | BLOCK:doh | ALLOW | POL-2/3: chặn endpoint DoH lab |
| T9.7 | BLOCK:doh | Chưa gửi request ngoài; thiếu rule POL-3 | POL-2/3: chặn DoH công khai |

SUPPORT ghi riêng: T1.5 expected BLOCK:social, actual ALLOW (POL-2/3); T6.7 ALLOW, PASS (limitation); T6.8 expected BLOCK:filetype, actual ALLOW (POL-3). Không quy FAIL thành PASS hay SKIP. Bản benchmark hiện tại chưa có overhead auth/ICAP đầy đủ, không dùng để kết luận hiệu năng cấu hình hoàn chỉnh.

## Gói bằng chứng riêng

PR bàn giao: [#3 — TLS/DOC-2](https://github.com/UIT24521892/NT140_SecureWebProxy/pull/3). Nhánh `tls/TLS-3-tv2-handoff`; SHA cuối của PR và checksum gói nằm trong README-evidence của ZIP, không tự tham chiếu SHA trong commit tài liệu này.

Push code và mở PR trước khi chốt ZIP. Gói giữ nguyên cây `docs/`, `results/tls/`, `results/bench/`, `captures/` để các liên kết tương đối đọc được sau giải nén. Gửi kèm `README-evidence.md`, `SHA256SUMS` cho mọi file (trừ chính manifest), và checksum `.zip.sha256` bên ngoài ZIP.

README của gói ghi URL PR, full PR-head SHA, SHA của lần chạy clone sạch, môi trường/phiên bản công cụ, thời điểm và lệnh tái lập. Kết quả 07/11 chưa ghi commit SHA khi chạy trên working tree chưa commit; không gán hồi tố chúng cho commit bàn giao. Lần chạy clone sạch trên commit cụ thể bổ sung khả năng đối chiếu. Nếu sau chạy chỉ sửa tài liệu, README phải nêu rõ diff và lý do không cần chạy lại runtime.

Chỉ đưa bốn pcap hiện có cùng các session key log tương ứng của lab, tóm tắt capture và kết quả gốc vào ZIP; không đưa `.env`, thư mục certs, CA/private key, htpasswd hay dữ liệu ngoài phạm vi. Session key log không commit Git. Bốn pcap chỉ có ba loại HTTP/splice/bump; capture TLS1.2 chẩn đoán không thay thế capture ICAP.

## Kiểm tra clone sạch ngày 2026-11-09

Commit runtime: `cbc7cb1f7dc75a5837b5838a87bc95f79c605f52`, clone chỉ từ Git, project `nt140-tls-review` và volume mới. Môi trường amd64: Docker Engine 29.3.1, Squid 6.14, OpenSSL 3.0.13, curl 8.5.0, Python container 3.12.3. Kết quả này bổ sung, không thay dữ liệu 07/11.

| Kiểm tra | Kết quả thật |
|---|---|
| Init/build/up, Compose config | Exit 0; tự sinh CA/pin/feed rỗng/work_hours/fixtures |
| ShellCheck, Python AST/py_compile | Exit 0; 12 shell script và 15 Python file |
| PKI/probe, testweb | 9/9 và 5/5 đạt |
| Splice/bump/selective | Hot-switch và `squid -k parse` exit 0 từng mode |
| [S7/S8/S9](../results/tls/20261109-164039-97a6bb/results.md) | 18/25; cùng 7 FAIL trong bảng trên, exit 1 |
| [SUPPORT](../results/tls/20261109-164106-e9beb5/results.md) | T6.7 PASS (limitation), T1.5/T6.8 FAIL, exit 1 |
| [Benchmark](../results/bench/20261109-164146-757587/bench.md) | 500 samples; B1/B2/B5/B6/B7 đạt, B3/B4/B8 SKIP có lý do |
| Phục hồi state và log | TLS selective, work_hours byte-identical, `.env` không bị runner sửa; parser THR-3 kiểm tra 16 trường thành công |
| Restart Squid | Restart/up --wait/parse exit 0; HTTPS probe ALLOW, issuer Proxy CA |
| P0 và runner S7/S8/S9 chung | Exit 2 từ Make: `not implemented yet (THR-2)`; chưa nghiệm thu |
| Bốn pcap gốc | Offline tshark giải mã GET client TLS1.3 và GET upstream TLS1.2 đúng frame/IP; chưa có ICAP |

Lệnh thật, stdout/stderr, thời điểm chạy, phiên bản và image IDs nằm trong `results/handoff/20261109/` của ZIP. Sau commit runtime chỉ cập nhật tài liệu bàn giao/progress/verify-log; README-evidence liệt kê diff theo full SHA. Không cần chạy lại runtime khi chỉ đổi các tài liệu đó.

Đã sửa entrypoint chung để xóa PID cũ trước `squid -z`, tránh restart loop; cần TV1 review. Trên host dùng Python portable, cấu hình `_pth` từng trỏ về repo cũ đã được loại trước lần chạy hợp lệ; runner được nạp với import path của clone. Lượt chạy sai môi trường không được tính là bằng chứng clone sạch. Không có thay đổi vào expected/scenario/probe schema hoặc parser THR-3.

Cần kiểm tra lại trên **arm64**, review DOC-2, ghép policy/cache/ICAP và runner toàn dự án, tạo capture ICAP và chụp ảnh Wireshark thật trước khi đánh dấu toàn bộ TV2 hoàn thành. TLS-8 chưa triển khai vì phần chính còn phụ thuộc các track khác.
