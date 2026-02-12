# WhiteHats - 自動化白帽安全測試框架

自動化白帽安全測試框架，提供 API 或 URL 即可自動掃描、產生測試案例、匯出獨立腳本。

## 流程圖

```
使用者輸入 (URL / API)
        │
        ▼
   ┌─────────┐    ┌────────────────────────────────────┐
   │   CLI   │───▶│          安全測試模組（8 個）        │
   └─────────┘    │  SQL注入 / XSS / CSRF / 安全標頭   │
        │         │  CORS / 資訊洩漏 / SSRF / 路徑遍歷  │
        │         └──────────────┬─────────────────────┘
        │                        │
        ▼                        ▼
   ┌─────────┐    ┌─────────┐    ┌──────────┐
   │ 產生測試 │    │ 掃描報告 │    │ 匯出腳本 │
   │ generate │    │ JSON/HTML│    │  export  │
   └────┬────┘    └────┬────┘    └────┬─────┘
        ▼              ▼              ▼
  test_cases/     reports/     standalone_*.py
```

## 架構

```
whiteHacker/
├── config/                    # 設定
├── whitehats/                 # 核心套件
│   ├── cli.py                 # CLI 進入點（scan / generate / export）
│   ├── config.py              # 設定載入
│   ├── models/                # 資料模型（Target / Vulnerability / TestCase）
│   ├── scanner/               # 掃描引擎（API / URL / 並行）
│   ├── modules/               # 安全模組（8 個插件式模組）
│   ├── generator/             # 測試產生器 + 獨立腳本匯出器
│   ├── payloads/              # 攻擊載荷（.txt）
│   └── reporter/              # 報告產生器（JSON / HTML）
├── tests/                     # 單元測試（83 項）
├── setup.py                   # 套件安裝
└── CLAUDE.md                  # AI 開發規範
```

## 使用方式

### 安裝

```bash
pip install .             # 安裝後用 whitehats 指令
# 或
pip install -r requirements.txt  # 用 python -m whitehats.cli
```

### 掃描

```bash
# 掃描 URL
whitehats scan --url https://example.com

# 掃描 API
whitehats scan --url https://example.com/api/users --api --method GET --params '{"id":"1"}'

# 掃描 API（帶認證）
whitehats scan --url https://example.com/api/login --api --method POST \
  --body '{"username":"test","password":"test123"}' --token "your-token"

# 多目標批次掃描（自動並行）
whitehats scan --targets-file config/targets_example.json

# 自訂設定
whitehats scan --url https://example.com -c my_config.yaml
```

### 產生測試案例

```bash
whitehats generate --url https://example.com/api/users --api --method GET
pytest test_cases/ -v
```

### 匯出拋棄式獨立腳本

```bash
whitehats export --list              # 列出可匯出的檔案
whitehats export 1                   # 用編號匯出
whitehats export 1 -o /tmp/scan.py   # 指定輸出位置

# 匯出的腳本完全獨立，只需 requests + pytest
pytest standalone_test_security_xxx.py -v
```

## 安全模組

| 模組 | CWE | 嚴重程度 |
|------|-----|----------|
| SQL 注入 | CWE-89 | 高 |
| XSS | CWE-79 | 高 |
| SSRF | CWE-918 | 高 |
| 路徑遍歷 | CWE-22 | 高 |
| CSRF | CWE-352 | 中 |
| 安全標頭 | CWE-16 | 中 |
| CORS 錯誤設定 | CWE-942 | 中 |
| 資訊洩漏 | CWE-200 | 依情況 |

## 擴充模組

```python
from whitehats.modules.base_module import BaseModule

class MyModule(BaseModule):
    name = "my_module"
    description = "自訂模組"

    def run(self, target, baseline_response):
        findings = []
        # 安全測試邏輯
        return findings
```

加入 `whitehats/modules/__init__.py` 的 `ALL_MODULES` 即可。

## 測試

```bash
pytest tests/ -v   # 83 項全部執行
```
