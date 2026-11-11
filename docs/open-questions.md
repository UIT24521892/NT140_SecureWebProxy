# Open questions

Ghi các câu hỏi về ngữ nghĩa policy hoặc phạm vi mà spec chưa trả lời, và các blocker liên quan tới track khác.
- Chỉ thêm dòng mới. Khi đã có trả lời thì cập nhật cột “Trạng thái”.

| # | Ngày | Người hỏi | Câu hỏi | Giả định tạm thời | Trạng thái / trả lời |
|---|---|---|---|---|---|
| 1 | 2026-11-11 | Claude (THR-4) | Fail-open (`ICAP_BYPASS=on`, icap dừng) cho EICAR đi qua và Squid **cache** luôn object đó; request sau tới cùng URL nhận `TCP_MEM_HIT/200` mà không qua ICAP, dù đã đặt lại `bypass=0` (quan sát trên arm64; lúc đó icap đang dừng, nếu có gọi ICAP thì phải ra 500). Có cần cấm cache khi bypass, hoặc xóa cache sau T5.13 không? | T5.13 dùng URL có query `?failopen=<runid>` để không làm bẩn cache cho T5.1 ở lần chạy sau. Hành vi này nên được nêu trong báo cáo như một rủi ro của fail-open | Mở |
