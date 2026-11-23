# Progress: trạng thái hiện tại

> File này được import vào `CLAUDE.md`, nên được nạp ở mọi phiên Claude Code.
> - Giữ toàn file **≤ 100 dòng**.
> - **Ghi đè** trạng thái hiện tại, không viết nhật ký. Lịch sử xem bằng `git log`.
> - Mỗi track chỉ sửa section của mình. Section “Chung” do TV1 cập nhật.

**Milestone hiện tại:** M1 đạt trên arm64; M2 (chức năng chính) đạt trên arm64 trừ T1.5 đang chờ quyết định. **Chưa có lần chạy amd64 nào cho bản ghép này.**
**Cập nhật lần cuối:** 2026-11-11, Claude trên máy TV1 (arm64): ghép PR #3 + POL-1, làm THR-2, THR-4, POL-2..6.

## Chung
- Môi trường: TV1 dùng Docker Desktop trên Mac M2 (arm64). Hướng dẫn chạy ở `README.md`; phần Windows/Linux chưa ai xác nhận.
- `main` có INF-1..3, THR-3, và PR #3 (TLS-1/2/3/4/5/6/7/9, DOC-2). PR #1 (POL-1) còn mở.
- **Nhánh làm việc `wip/m2-integration` (tách từ `main`, toàn bộ CHƯA COMMIT):** POL-1 (áp từ nhánh PR #1) + sửa dryrun + THR-2 + THR-4 + POL-2..6. Cần tách commit/PR theo task trước khi merge.
- `make up`: 6 service chạy (squid, icap, clamav, testweb `healthy`; 2 client `Up`). Profile chưa bật: `dashboard`, `capture`, `p2`.
- `make test` (arm64, 11/11): **74 case: 63 PASS, 10 PASS (limitation), 1 FAIL (T1.5), 0 SKIP**. Có module S0, S1, S2, S5, S6, S7, S8, S9, S10. Chưa có S3, S4, S11.
- Câu hỏi mở (`docs/open-questions.md`): #1 fail-open làm bẩn cache; #2 T1.5 guest HTTPS bị chặn ra `TLS_ERROR`.
- `squid -k parse`: không ERROR/FATAL; 1 WARNING `empty ACL threat_ips` khi feed rỗng (đã giải thích ở verify-log).

## Track INF/POL (TV1, arm64)
- Xong trên `main`: INF-1, INF-2, INF-3.
- Xong trên nhánh làm việc, chưa commit, đã kiểm arm64:
  - POL-1: auth + nhóm (T1.8, T2.1, T2.2 PASS).
  - POL-2: `policy/lists/local/*.txt`, `conf.d/11-acl-lists.conf`, `13-acl-misc.conf` (đúng tên ACL spec §5.2).
  - POL-3: `40-access.conf` đúng thứ tự §5.4 (có `!dryrun` trước 2 rule `dst`), `41-reply-access.conf`, `70-errors.conf`, trang chặn sinh từ `errors/ERR_LAB.tmpl` + `reasons.tsv`.
  - POL-4: `scripts/set-worktime.sh`, `make worktime` (T2.4–T2.8 PASS).
  - POL-5: `50-cache.conf`, `templates/delay.conf.tmpl` (S10 4/4 PASS).
  - POL-6: `s01`, `s02`, `s06`, `s10`. S2 10/10, S6 8/8, S10 4/4, S1 7/8.
- Sửa dryrun: request `X-Lab-Dryrun` không còn gây tra DNS (verify-log 11/11); `conf.d/14-dryrun.conf` thuộc THR-5, tạo sớm.
- Bước tiếp: quyết T1.5 (open-questions #2); DOC-1; nghiệm thu amd64; review/merge.
- Blocker: cần người chạy amd64 và review theo plan §4.

## Track TLS (TV2, amd64)
- Đã merge PR #3: TLS-1/2/3/4/5/6/7/9, DOC-2. TLS-8 (stretch) chưa làm.
- Gác cổng arm64 (Claude, 11/11): unit test `tests/tls` 9 OK; 3 mode đổi được; `scripts/test_tls.py` 18/25 giống amd64. Sau khi ghép POL: S7 8/8, S8 9/9, S9 8/8 qua runner chung.
- Việc còn lại đề xuất cho TV2: bỏ `scripts/test_tls.py`, `tls_support.py`, target `test-tls` (trùng với `tests/run_all.py`); xem lại `docs/trung-handoff.md` (ngoài spec §16, nội dung đã cũ); `/` của testweb đang có `Cache-Control: public` (spec §8 không yêu cầu); chạy `make bench` đủ B1–B8 khi cache và ICAP đã có.
- Blocker: —

## Track THR (TV3, amd64)
- THR-3: merge ở PR #2 (tự merge, chưa review). TV1 review 12/11 yêu cầu sửa parser; đang sửa ở nhánh `thr/THR-3-parser-fix`:
  - `test_id` gộp `T.X,%20T.X` (HTTP gửi cả `-H` và `--proxy-header`) → chuẩn hóa về `T.X`.
  - `mark()` + tham số `since` (`records_for`, `find_by_test_id`, `connection_records`, `all_records`, `best_record`, CLI `--since`) để không lấy dòng log của lần chạy trước.
  - Unit test `python3 tests/lib/test_squidlog.py`: 12 OK (bản cũ: 4 FAIL, 6 ERROR). Chưa chạy lab amd64.
  - Còn phải kiểm trên amd64: quyền đọc log (umask, review mục 5), lệnh nghiệm thu của TV1.
- THR-2, THR-4: đã merge (PR #5, #6). Runner chưa dùng `since` (đã có run id riêng mỗi lần chạy); dùng khi làm T11.1 (THR-6).
- Chưa làm: THR-5 (feed, S3), THR-6 (S4, S11), THR-7 (log summary, goaccess), THR-8, DOC-3.
- Câu hỏi mở: #3 nguồn dữ liệu đếm virus cho §10.2.
- Blocker: chưa chạy được lab trên máy amd64 (WSL đang là WSL 1).

## Kết quả test gần nhất
| Ngày | Arch | Lệnh | Kết quả |
|---|---|---|---|
| 2026-11-11 | arm64 | `make init`; `make up`; `make test`; `make test P=P0`; `squid -k parse`; `make lint` | 74 case: 63 PASS, 10 PASS (limitation), 1 FAIL (T1.5), 0 SKIP. Lint đạt (16 `.sh`, 24 `.py`) |
| 2026-11-09 | amd64 | PR #3 trên clone sạch (TV2/Codex) | `scripts/test_tls.py` 18/25 trước khi có POL |
| 2026-11-09 | arm64 | POL-1: auth HTTP/HTTPS, log THR-3, cô lập mạng | 31/31 kiểm tra độc lập đạt |
