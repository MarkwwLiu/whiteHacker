# WhiteHats - 自動化白帽安全測試框架

基於 Python 的自動化白帽安全測試框架。只需提供 API 端點或 URL，即可自動產生並執行安全測試案例。

## 架構

```
whiteHacker/
├── config/
│   ├── default_config.yaml        # 預設掃描設定
│   └── targets_example.json       # 多目標範例檔
├── whitehats/                     # 核心框架套件
│   ├── cli.py                     # CLI 進入點
│   ├── config.py                  # 設定載入器
│   ├── models/                    # 資料模型
│   │   ├── target.py              # 目標模型 (API/URL)
│   │   ├── vulnerability.py       # 漏洞發現模型
│   │   └── test_case.py           # 測試案例模型
│   ├── scanner/                   # 掃描引擎
│   │   ├── base_scanner.py        # 抽象基底掃描器
│   │   ├── api_scanner.py         # API 端點掃描器
│   │   ├── url_scanner.py         # URL 頁面掃描器
│   │   └── concurrent_scanner.py  # 並行多目標掃描器
│   ├── modules/                   # 安全測試模組（插件式）
│   │   ├── base_module.py         # 抽象基底模組
│   │   ├── sql_injection.py       # SQL 注入偵測
│   │   ├── xss.py                 # 跨站腳本攻擊偵測
│   │   ├── csrf.py                # CSRF 防護檢查
│   │   ├── header_security.py     # 安全標頭稽核
│   │   ├── cors_misconfig.py      # CORS 錯誤設定檢查
│   │   ├── info_disclosure.py     # 資訊洩漏檢查
│   │   ├── ssrf.py                # SSRF 偵測
│   │   └── path_traversal.py      # 路徑遍歷 / LFI 偵測
│   ├── generator/                 # 測試案例自動產生器
│   │   ├── test_generator.py      # 產生 pytest 測試檔
│   │   ├── template_engine.py     # 測試檔範本引擎
│   │   └── standalone_exporter.py # 拋棄式獨立腳本匯出器
│   ├── payloads/                  # 攻擊載荷資料
│   │   ├── sql_payloads.txt
│   │   ├── xss_payloads.txt
│   │   ├── ssrf_payloads.txt
│   │   └── path_traversal_payloads.txt
│   └── reporter/                  # 報告產生器
│       ├── base_reporter.py
│       ├── json_reporter.py       # JSON 格式報告
│       └── html_reporter.py       # HTML 格式報告
├── test_cases/                    # 自動產生的測試案例（解耦，獨立存放）
├── reports/                       # 產出的報告
├── tests/                         # 框架本身的單元測試（83 項）
└── setup.py                       # 套件安裝設定
```

## 流程圖

```
                    ┌─────────────────┐
                    │   使用者輸入     │
                    │  (API / URL)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  CLI / 設定檔   │
                    │   解析目標      │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  API 掃描器      │          │  URL 掃描器     │
     │  (APITarget)    │          │  (URLTarget)    │
     └────────┬────────┘          └────────┬────────┘
              │                             │
              └──────────┬──────────────────┘
                         │
                ┌────────▼────────┐
                │  並行掃描引擎    │  ← 多目標時自動啟用
                │ (ThreadPool)    │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │  安全測試模組    │
                │  （插件式）      │
                ├─────────────────┤
                │ • SQL 注入      │
                │ • XSS           │
                │ • CSRF          │
                │ • 安全標頭      │
                │ • CORS          │
                │ • 資訊洩漏      │
                │ • SSRF          │
                │ • 路徑遍歷      │
                └────────┬────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
 ┌────────▼───────┐ ┌───▼──────────┐ ┌─▼───────────────┐
 │ 測試案例產生器  │ │ 報告產生器   │ │ 獨立腳本匯出器  │
 │ (pytest 檔案)  │ │ (JSON/HTML)  │ │ (export 指令)   │
 └────────┬───────┘ └───┬──────────┘ └─┬───────────────┘
          │             │              │
 ┌────────▼───────┐ ┌───▼──────────┐ ┌─▼───────────────┐
 │ test_cases/    │ │ reports/     │ │ standalone_*.py │
 │ （解耦獨立）   │ │ （輸出結果）  │ │ （拋棄式腳本）  │
 └────────────────┘ └──────────────┘ └─────────────────┘
```

## 安裝

### 方法一：pip install（推薦）

```bash
pip install .
```

安裝後即可直接使用 `whitehats` 指令：

```bash
whitehats scan --url https://example.com
```

### 方法二：使用 requirements.txt

```bash
pip install -r requirements.txt
python -m whitehats.cli scan --url https://example.com
```

### 開發者安裝

```bash
pip install -e ".[dev]"
```

## 使用方式

### 1. 掃描單一 URL

```bash
whitehats scan --url https://example.com
```

### 2. 掃描 API 端點

```bash
whitehats scan --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

### 3. 掃描帶有 POST 請求體與認證 Token 的 API

```bash
whitehats scan \
  --url https://example.com/api/login \
  --api \
  --method POST \
  --body '{"username": "test", "password": "test123"}' \
  --token "your-bearer-token"
```

### 4. 從檔案掃描多個目標（自動並行）

```bash
whitehats scan --targets-file config/targets_example.json
```

多目標時框架會自動啟用 **並行掃描**（`ThreadPoolExecutor`），依據設定的 `max_concurrent` 控制同時執行數：

```yaml
# config/default_config.yaml
scan:
  max_concurrent: 5   # 最大並行數
```

### 5. 僅產生測試案例（不執行掃描）

```bash
whitehats generate --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

接著執行產生的測試：

```bash
pytest test_cases/
```

### 6. 匯出拋棄式獨立腳本

產生測試案例後，可以將指定的測試檔匯出為**完全獨立**的單檔腳本。匯出的腳本不依賴框架，只需 `requests` + `pytest` 即可在任何機器上執行。

```bash
# 列出可匯出的測試檔
whitehats export --list
#   [1] test_cases/test_security_examplecom_api_users.py
#   [2] test_cases/test_security_examplecom.py

# 用完整路徑匯出
whitehats export test_cases/test_security_examplecom_api_users.py

# 用編號快速匯出
whitehats export 1

# 指定輸出位置
whitehats export 1 -o /tmp/scan_users.py
```

匯出後在任何機器上執行：

```bash
pip install requests pytest
pytest standalone_test_security_examplecom_api_users.py -v
```

匯出的腳本包含：
- 內嵌的 pytest fixture（取代 conftest.py）
- 完整的測試類別與 payload
- 所有必要的 import

### 7. 使用自訂設定檔

```bash
whitehats scan --url https://example.com -c my_config.yaml
```

## CLI 指令總覽

| 指令 | 說明 |
|------|------|
| `whitehats scan` | 執行安全掃描 |
| `whitehats generate` | 僅產生測試案例（不掃描） |
| `whitehats export` | 匯出拋棄式獨立測試腳本 |
| `whitehats export --list` | 列出可匯出的測試檔案 |

## 安全測試模組

| 模組 | 說明 | 嚴重程度 | CWE |
|------|------|----------|-----|
| SQL 注入 | 測試參數與請求體是否存在 SQL 注入漏洞 | 高 | CWE-89 |
| XSS | 測試是否存在反射型跨站腳本攻擊 | 高 | CWE-79 |
| CSRF | 檢查 CSRF Token 與 SameSite Cookie 設定 | 中 | CWE-352 |
| 安全標頭 | 稽核安全標頭（HSTS、CSP 等） | 中 | CWE-16 |
| CORS 錯誤設定 | 測試 CORS 萬用字元、來源反射、空來源 | 中 | CWE-942 |
| 資訊洩漏 | 掃描回應中是否洩漏敏感資料 | 依情況 | CWE-200 |
| SSRF | 偵測伺服器端請求偽造，包含雲端 metadata 洩漏 | 高 | CWE-918 |
| 路徑遍歷 | 偵測路徑遍歷 / LFI 漏洞，讀取任意檔案 | 高 | CWE-22 |

## 新增自訂模組

在 `whitehats/modules/` 目錄下建立新檔案，繼承 `BaseModule`：

```python
from whitehats.modules.base_module import BaseModule
from whitehats.models.vulnerability import Vulnerability, Severity

class MyCustomModule(BaseModule):
    name = "my_custom"
    description = "自訂安全檢查模組"

    def run(self, target, baseline_response):
        findings = []
        # 在此撰寫安全測試邏輯
        return findings
```

然後將其加入 `whitehats/modules/__init__.py` 的 `ALL_MODULES` 清單中。

## 目標檔案格式

```json
{
  "targets": [
    {
      "type": "api",
      "url": "https://example.com/api/endpoint",
      "method": "POST",
      "params": {},
      "headers": {"Content-Type": "application/json"},
      "body": {"key": "value"},
      "auth_token": "選填的認證 Token"
    },
    {
      "type": "url",
      "url": "https://example.com/page"
    }
  ]
}
```

## 測試

框架本身包含 83 項單元測試，涵蓋所有核心模組：

```bash
# 執行全部測試
pytest tests/ -v

# 執行特定測試
pytest tests/test_modules.py -v      # 安全模組測試
pytest tests/test_scanner.py -v      # 掃描器測試
pytest tests/test_exporter.py -v     # 匯出器測試
```

| 測試檔案 | 涵蓋內容 | 數量 |
|----------|---------|------|
| `test_models.py` | Target、Vulnerability、TestCase 模型 | 11 |
| `test_config.py` | 設定載入、deep merge | 9 |
| `test_modules.py` | 全部 8 個安全模組 | 30 |
| `test_scanner.py` | APIScanner、URLScanner | 8 |
| `test_reporter.py` | JSON / HTML 報告產生 | 6 |
| `test_concurrent_scanner.py` | 並行掃描 | 5 |
| `test_exporter.py` | 拋棄式腳本匯出 | 8 |
