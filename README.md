# open-appsec 修正版

這個儲存庫是 open-appsec 主程式（agent）的 fork。`local-fixes` 分支修正了以下幾類問題：

- 政策產生、自訂回應與重試
- 限速與 Redis
- Snort 規則轉換
- 壓縮與 WAAP 解析
- IPS 執行期
- IPC 權限與 REST 服務

## 出處

| 項目 | 內容 |
|---|---|
| 上游專案 | [openappsec/openappsec](https://github.com/openappsec/openappsec) |
| 修正的基底版本 | 上游 `main` 的 commit [`634f840`](https://github.com/openappsec/openappsec/commit/634f840534e07952b1a449079a0d1b2e885c6aec) |
| 原本的 README | [上游 README](https://github.com/openappsec/openappsec/blob/634f840534e07952b1a449079a0d1b2e885c6aec/README.md)，內容包括專案介紹、部署方式和編譯步驟 |
| open-appsec 網站與文件 | [openappsec.io](https://www.openappsec.io)、[docs.openappsec.io](https://docs.openappsec.io/) |
| 授權 | 與上游相同，見 [LICENSE](LICENSE) |

本 fork 的 `main` 分支已合併 `local-fixes` 分支。

## 相關的 fork

agent 搭配的 attachment（Kong 外掛與 NGINX 模組）修正在 [dark610172/attachment](https://github.com/dark610172/attachment)。

## 分支

| 分支 | 內容 | 詳細文件 |
|---|---|---|
| [`local-fixes`](https://github.com/dark610172/openappsec/tree/local-fixes) | 47 個 commit，修改 124 個檔案 | [docs/local-fixes-report.md](docs/local-fixes-report.md) |

每一項修正的 commit、上游 issue 編號和驗證方式，見詳細文件。

## 改善內容

| 類別 | 修正前 | 修正後 |
|---|---|---|
| 建置 | Boost 1.86 以上和新版 CMake 無法編譯 | 可以編譯；`rest_server_ut` 的環境假設也已修正 |
| 自訂回應 | 限速封鎖和沒有回應 ID 的 DROP 會回 274,686 位元組的 Check Point 頁面 | 使用規則指定的回應，例如空本文 403 |
| 政策產生 | 多個資產共用限速設定時只有最後一個生效；一條規則引用多個例外時只有第一個生效；v1beta1 把 error disclosure、CSRF、open redirect 寫死成停用；`nonValidHttpMethods` 設定無效；`syslogService`、`cefService` 用陣列格式時遠端日誌無聲失效 | 都依政策設定產生 |
| 政策寫入與重試 | 產生失敗仍提交版本號，相同內容不再重試；寫檔不檢查結果；失敗後殘留舊狀態 | 先寫暫存檔再原子替換；失敗不提交版本，會重試 |
| Snort 規則轉換 | 暫存路徑錯誤、規則無聲消失；2 條規則讓整個政策產生失敗 | 記錄並略過無法轉換的規則；全部失敗時才讓政策產生失敗 |
| 限速 | `0.0.0.0/0` 只符合 `0.0.0.0`，規則永遠不命中；Redis 腳本快取被清除後限速永久失效；Redis 卡住時每個請求停 6 秒；IPv6 來源被當成 IPv4 | `/0` 涵蓋所有位址；自動重新載入腳本；設定命令逾時；IPv4 與 IPv6 都正確 |
| 壓縮 | gzip 只解第一個成員，攻擊放在第二個成員就漏擋；解壓輸出沒有上限；`ParserGzip` 漏記憶體 | 解開每個成員；每個串流上限 256 MiB；緩衝區都會釋放 |
| WAAP 解析 | JSON 深度沒算空容器和陣列；含點號的鍵名被拆錯；非 ASCII 字元被刪掉，讓相鄰的字母接成關鍵字 | 深度正確；鍵名保留；非 ASCII 字元改成空格 |
| IPS | 只看回應狀態碼或回應標頭的規則，在回應到達前就放行；`HTTP_RAW` 比對被本文資料塊切斷 | 在回應階段檢查；補回標頭與本文的邊界 |
| IPC 權限 | 佇列檔權限 `0666`，本機任何使用者都能讀寫 | 擁有者交給 attachment，權限 `0660` |
| REST 服務 | 只送半個請求就能卡住整個主迴圈 | 非阻塞讀取，10 秒沒有活動就逾時 |
| 其他 | manifest 缺少依賴或循環依賴會當掉；Prometheus 白名單漏掉指標；`shell_cmd` 遇到 NUL 位元組截斷 | 都已修 |

## 測試架構與資源配置

### 實體主機

所有 VM 都在同一台 Proxmox VE 主機上，網路走同一個虛擬橋接器，流量不經過外部網路。

| 項目 | 規格 |
|---|---|
| CPU | AMD Ryzen 5 5600X，6 核 12 執行緒 |
| 記憶體 | 62 GB |
| 虛擬化 | Proxmox VE 9.2，VM 使用 `cpu host`，不啟用記憶體氣球 |

### VM 與用途

```
VM117 測試機 ──HTTP──▶ VM112 被測系統（Kong + open-appsec agent） ──▶ VM113 後端
                       VM123 建置機：編譯、單元測試、雲端中控測試
```

| VM | 角色 | vCPU | 記憶體 | 內容 |
|---|---|---|---|---|
| VM123 | 建置與單元測試 | 8 | 16 GB | Ubuntu 26.04.1、Boost 1.90、Docker。另外跑雲端中控（online 模式）測試的 agent、Kong 和後端容器 |
| VM112 | 被測系統 | 6 | 32 GB | Ubuntu 26.04.1、Docker、Kong Gateway 3.14 LTS、open-appsec agent（用 Alpine 重新建置的二進位檔） |
| VM113 | 後端 | 2 | 4 GB | 測試用後端應用 |
| VM117 | 測試機 | 4 | 12 GB | Ubuntu 26.04.1、wrk 4.1.0 |

### 量測方法

- 每一項修正都要做「還原後失敗」檢查：先移除修正，新測試必須失敗；放回修正後，測試必須通過。
- 每個 commit 都經過獨立程式碼審查。審查找到的問題，另外用新的 commit 修正。
- 實測時，原版和修正版整組替換：handler、orchestration 和三個共用函式庫，然後重啟 Kong。
- 效能測試的順序是原版、修正版、修正版、原版。每個情境量測前先暖機 60 秒，暖機結果不計入。
- 測試機和被測系統在不同的 VM。

## 測試結果

### 單元測試

- 完整單元測試 53 個全部通過。`connection_comp_ut` 會和測試機的 8080 埠衝突，所以沒有列入。
- 新增的測試目標：`local_policy_mgmt_gen_ut`、`declarative_policy_utils_ut`、`rate_limit_ut`、`waap_parsers_ut`、`manifest_diff_calculator_ut`、`rest_conn_ut`、`nginx_attachment_config_ut`、`shell_cmd_ut`。

### 防護與功能實測

| 項目 | 原版 | 修正版 |
|---|---|---|
| 兩個 gzip 成員，攻擊放在第二個 | 放行 | 403 |
| 深層 JSON 的空容器和陣列 | 放行 | 403 |
| Snort 回應狀態碼規則（404） | 404 直接放行 | 403 |
| `0.0.0.0/0` 限速規則，每分鐘 50 次 | 80 個請求全部 200 | 前 50 個 200，後 30 個 403 |
| Redis 腳本快取被清除 | 之後全部放行 | 第 3 個請求起恢復封鎖 |
| Redis 卡住不回應 | 每個請求停 6 秒 | 約 30 毫秒後放行 |
| 1,200 個 gzip 請求後的 handler 記憶體 | 增加約 515 MB | 增加 16 MB 後保持穩定 |
| 只送半個 REST 請求 | REST 服務卡住，正常請求 5 秒逾時 | 正常請求 0.02 秒回應 |
| IPC 佇列檔權限 | `0666` | `0660`，其他 UID 讀取被拒 |
| 限速封鎖的回應 | 274,686 位元組的頁面 | 空本文 403 |

雲端中控（online 模式）的測試結果：

- 修正版可以註冊，也能下載政策和 manifest、上傳事件。
- XSS、路徑穿越、命令注入、log4j、XXE、gzip 攻擊都被擋（403），正常請求是 200。

### 效能

情境有 GET、50 KB POST、XSS，並行數 16、64、256，每組跑 2 次，每次 30 秒。

| 項目 | 結果 |
|---|---|
| XSS | 修正版快約 40%。被擋時回空本文，不再送出 274,686 位元組的頁面 |
| GET | 修正版約每秒 3,560 個請求，比原版慢。原因是 IPS 預設檢查 `HTTP_RAW`。不檢查 `HTTP_RAW` 的版本約每秒 4,020 個，所以檢查的成本約 12% |
| 混合負載（8 執行緒，GET、20 KB POST、gzip POST） | 差異在雜訊範圍內，沒有可辨識的退步 |

## 部署注意事項

- 部署時要一起換掉 handler 和這三個函式庫：`libngen_core.so`、`libcompression_utils.so`、`libshmem_ipc.so`。只換 handler，部分修正不會生效。
- 部署後一定要重跑攻擊測試，確認新的檔案已經生效。
- Redis 命令逾時沿用 Redis Timeout 設定，預設 30 毫秒。Redis 回應比這個慢時，限速會放行並重新連線。
- 非空的 Snort 檔如果全部規則都轉換失敗，政策產生會失敗。原本是無聲略過。

## 已知限制

- 解壓輸出上限 256 MiB 只有單元測試驗證。用 gzip 炸彈實測時，原版和修正版的記憶體峰值差不多。
- IPv6 限速、含點號的鍵名、manifest 依賴檢查、跨 user namespace 的 IPC 權限，都只有單元測試驗證。
- 雲端中控測試時，Snort 規則 9100102 沒有送到雲端政策，原因還沒查明。
- handler 被強制結束後，watchdog 在 1 秒內重新啟動它，但 Kong 會持續放行超過 5 分鐘。原版也一樣。
- 被測環境沒有經過 open-appsec 的學習期。
- 所有 VM 在同一台實體主機上，彼此會共用 CPU。

沒有修正的項目和原因，見 [docs/local-fixes-report.md](docs/local-fixes-report.md)。

## 編譯

編譯步驟和上游相同，見[上游 README](https://github.com/openappsec/openappsec/blob/634f840534e07952b1a449079a0d1b2e885c6aec/README.md)。這個分支已修正 Boost 1.86 以上和新版 CMake 的編譯問題。
