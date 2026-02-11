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
│   │   └── url_scanner.py         # URL 頁面掃描器
│   ├── modules/                   # 安全測試模組（插件式）
│   │   ├── base_module.py         # 抽象基底模組
│   │   ├── sql_injection.py       # SQL 注入偵測
│   │   ├── xss.py                 # 跨站腳本攻擊偵測
│   │   ├── csrf.py                # CSRF 防護檢查
│   │   ├── header_security.py     # 安全標頭稽核
│   │   ├── cors_misconfig.py      # CORS 錯誤設定檢查
│   │   └── info_disclosure.py     # 資訊洩漏檢查
│   ├── generator/                 # 測試案例自動產生器
│   │   ├── test_generator.py      # 產生 pytest 測試檔
│   │   └── template_engine.py     # 測試檔範本引擎
│   ├── payloads/                  # 攻擊載荷資料
│   │   ├── sql_payloads.txt
│   │   └── xss_payloads.txt
│   └── reporter/                  # 報告產生器
│       ├── base_reporter.py
│       ├── json_reporter.py       # JSON 格式報告
│       └── html_reporter.py       # HTML 格式報告
├── test_cases/                    # 自動產生的測試案例（解耦，獨立存放）
├── reports/                       # 產出的報告
└── tests/                         # 框架本身的單元測試
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
              └──────────────┬──────────────┘
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
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  測試案例產生器   │          │  報告產生器     │
     │  (pytest 檔案)  │          │  (JSON / HTML)  │
     └────────┬────────┘          └────────┬────────┘
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  test_cases/    │          │  reports/       │
     │  （解耦獨立）    │          │  （輸出結果）    │
     └─────────────────┘          └─────────────────┘
```

## 安裝

```bash
pip install -r requirements.txt
```

## 使用方式

### 1. 掃描單一 URL

```bash
python -m whitehats.cli scan --url https://example.com
```

### 2. 掃描 API 端點

```bash
python -m whitehats.cli scan --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

### 3. 掃描帶有 POST 請求體與認證 Token 的 API

```bash
python -m whitehats.cli scan \
  --url https://example.com/api/login \
  --api \
  --method POST \
  --body '{"username": "test", "password": "test123"}' \
  --token "your-bearer-token"
```

### 4. 從檔案掃描多個目標

```bash
python -m whitehats.cli scan --targets-file config/targets_example.json
```

### 5. 僅產生測試案例（不執行掃描）

```bash
python -m whitehats.cli generate --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

接著執行產生的測試：

```bash
pytest test_cases/
```

### 6. 使用自訂設定檔

```bash
python -m whitehats.cli scan --url https://example.com -c my_config.yaml
```

## 安全測試模組

| 模組 | 說明 | 嚴重程度 |
|------|------|----------|
| SQL 注入 | 測試參數與請求體是否存在 SQL 注入漏洞 | 高 |
| XSS | 測試是否存在反射型跨站腳本攻擊 | 高 |
| CSRF | 檢查 CSRF Token 與 SameSite Cookie 設定 | 中 |
| 安全標頭 | 稽核安全標頭（HSTS、CSP 等） | 中 |
| CORS 錯誤設定 | 測試 CORS 萬用字元、來源反射、空來源 | 中 |
| 資訊洩漏 | 掃描回應中是否洩漏敏感資料 | 依情況 |

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
