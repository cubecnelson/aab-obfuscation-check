# aab-obfuscation-check

從 Android App Bundle（`.aab`）估算 **R8 / ProGuard 風格混淆比例**（純 Python，唔使 Android Studio／SDK）。

Estimate **R8/ProGuard-style obfuscation percentage** from an `.aab` (pure Python; no Android Studio/SDK).

## 做咩 / What it does

1. 把 `.aab` 當 ZIP 解開，搵 `base/dex/classes*.dex`（同 feature module 嘅 `*/dex/*.dex`）
2. 解析 DEX class（同 method）名稱
3. 用 heuristic 判斷係咪短名混淆（例如 `a.b.c`、`a`、`ab`）
4. 預設 **排除** `android.*` / `androidx.*` / `kotlin*` / `java.*` 等 SDK／library，百分比只計「app／其餘」class
5. 輸出文字報告，或 `--json`

亦支援 `.apk`（根目錄 `classes*.dex`）同單獨 `.dex`。

## 快速使用 / Quick start

```bash
cd /workspace/aab-obfuscation-check   # or wherever you cloned this

# 文字報告
./check_obfuscation.py /path/to/app.aab

# JSON
./check_obfuscation.py /path/to/app.aab --json

# 唔計 method、額外排除自家 SDK
./check_obfuscation.py app.aab --no-methods --exclude-prefix com.squareup.
```

**依賴：** 只要 Python 3.9+。`requirements.txt` 係空（刻意零第三方）。

## 合成測試 / Synthetic smoke test

```bash
python3 make_synthetic_aab.py
./check_obfuscation.py testdata/sample.aab
```

預期大概：`App class obfuscation : 62.50%`（5 obfuscated / 8 app classes）。

## 指標說明 / Metrics

| 欄位 | 意思 |
|------|------|
| `total_classes` | DEX 內 unique class 數 |
| `library_classes` | 被 exclude prefix 剔走（唔入 %） |
| `app_classes` | 其餘（當 app／third-party 未剔） |
| `obfuscated_app_classes` | 短名 heuristic 判為混淆 |
| `obfuscation_percent` | `obfuscated / app_classes * 100` |
| `method_obfuscation_percent` | app class 內 method 名同樣 heuristic（可選） |

**混淆 heuristic（class）：**

- simple name 符合 `^[a-z]{1,3}\d*$`（`a`、`ab`、`abc`、`a1`）
- 或多數 package segment 係單字母短名（`a.b.c`）
- inner class：`Outer$a` / `a$b` 亦會計

**唔係安全證明：** 只係名稱型態統計；keep rules、dictionary、非 R8 混淆、native 碼都唔會反映。

## 選項 / Flags

```
positional:
  aab                         .aab / .apk / .dex 路徑

optional:
  --json                      JSON 輸出
  --no-methods                跳過 method 統計
  --include-library-in-percent
                              唔排除 SDK，全部 class 計入 %
  --exclude-prefix PREFIX     額外排除（可重複）；會自動補句號
  --sample N                  sample 名數量（預設 12）
```

## 檔案 / Layout

```
aab-obfuscation-check/
├── check_obfuscation.py      # 主程式
├── make_synthetic_aab.py     # 產生 testdata/sample.aab
├── requirements.txt          # 無第三方依賴
├── README.md
└── testdata/                 # make_synthetic_aab.py 產生
    ├── classes.dex
    └── sample.aab
```

## 限制 / Limits

- AAB 內 DEX 喺 `*/dex/`；若只得 protobuf／未解壓 module，會報「No DEX found」
- 唔會跑 `bundletool`；唔使下載 JAR
- 多 DEX／feature module 會合併後 **按 class 名去重**
- 名稱用 MUTF-8 近似解碼；一般 ASCII class 名冇問題

## Example output

```
AAB/APK/DEX : app-release.aab
DEX files   : 2
  - base/dex/classes.dex
  - base/dex/classes2.dex

Total classes (unique) : 18420
  Library / SDK        : 12100  (excluded from %)
  App / other          : 6320
    Obfuscated         : 5981
    Readable           : 339

>>> App class obfuscation : 94.63%
>>> App method obfuscation: 91.20% (40211/44090)
```
