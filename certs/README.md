# certs/

Do `scripts/gen-certs.sh` sinh ra (chạy qua `make init`), xem spec §3. Mọi file trong thư mục này đều bị gitignore, trừ README này.

| File | Vai trò | Ai tin |
|---|---|---|
| `lab-public-ca.crt/.key` | CA giả lập Web PKI công khai | mọi client + squid |
| `testweb.crt/.key` | cert `*.lab.test` của testweb, ký bởi lab-public-ca | — |
| `lab-proxy-ca.crt/.key` | CA của proxy để SslBump | chỉ `client-staff` |
| `pinned.sha256` | SPKI pin của testweb cho `curl --pinnedpubkey` | — |

Muốn sinh lại toàn bộ: `scripts/gen-certs.sh --force`. Sau đó phải chạy `make up` lại để các container nạp cert mới.
