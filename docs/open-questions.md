# Open questions

Ghi các câu hỏi về ngữ nghĩa policy hoặc phạm vi mà spec chưa trả lời, và các blocker liên quan tới track khác.
- Chỉ thêm dòng mới. Khi đã có trả lời thì cập nhật cột “Trạng thái”.

| # | Ngày | Người hỏi | Câu hỏi | Giả định tạm thời | Trạng thái / trả lời |
|---|---|---|---|---|---|
| 1 | 2026-11-11 | Claude (THR-4) | Fail-open (`ICAP_BYPASS=on`, icap dừng) cho EICAR đi qua và Squid **cache** luôn object đó; request sau tới cùng URL nhận `TCP_MEM_HIT/200` mà không qua ICAP, dù đã đặt lại `bypass=0` (quan sát trên arm64; lúc đó icap đang dừng, nếu có gọi ICAP thì phải ra 500). Có cần cấm cache khi bypass, hoặc xóa cache sau T5.13 không? | T5.13 dùng URL có query `?failopen=<runid>` để không làm bẩn cache cho T5.1 ở lần chạy sau. Hành vi này nên được nêu trong báo cáo như một rủi ro của fail-open | Mở |
| 2 | 2026-11-11 | Claude (POL-3/POL-6) | T1.5 (guest, `https://social.lab.test/`) spec mong `BLOCK:social`, thực tế `TLS_ERROR`: Squid trả 200 cho CONNECT rồi bump để đưa trang chặn, guest không tin Proxy CA nên lỗi cert. Việc chặn vẫn có hiệu lực (log `TCP_DENIED/200 policy=social`). T4.3 (guest, HTTPS phishing) nhiều khả năng gặp cùng hiện tượng. Sửa expect của T1.5/T4.3 thành `TLS_ERROR` kèm kiểm tra `policy` trong log, hay tìm cấu hình trả 403 cho CONNECT? | Giữ nguyên expect, T1.5 đang FAIL | Mở |
| 3 | 2026-11-12 | Claude/TV3 (THR-3, THR-7) | §10.2 yêu cầu `log_summary.py` đếm “số lần ICAP phát hiện virus”, nhưng trường 14 `%adapt::sum_trs` chỉ là thời gian và `policy` của request bị ICAP chặn là `-` (verify-log 11/11). Lấy số liệu từ đâu: (a) thêm trường kiểu `%{X-Infection-Found}adapt::<last_h` vào logformat (đổi §10.1, cần verify tên token), (b) đọc log của c-icap, (c) suy từ `TCP_MISS/403` + `mime`/URL trong `access_lab.log`? | Tạm dùng (b) cho THR-7; chưa đổi logformat | Mở |
