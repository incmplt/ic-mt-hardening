# ic-mt-hardening

Movable Type のバージョン、`mt-config.cgi`、プラグイン、テーマ、CGI/設定ファイルのパーミッション、Perl 実行環境をまとめて確認し、Markdown または JSON レポートを出力する CLI ツールです。

対象は同じサーバー上にあるローカルの Movable Type アプリケーションルートです。Python 標準ライブラリのみで動きます。

## 使い方

```bash
python -m ic_mt_hardening /path/to/mt -o report.md
```

インストールしてコマンドとして使う場合:

```bash
pip install .
ic-mt-hardening /path/to/mt -o report.md
```

JSON レポートを出力する場合:

```bash
ic-mt-hardening /path/to/mt --format json -o report.json
```

`mt-config.cgi` を明示する場合:

```bash
ic-mt-hardening /path/to/mt --mt-config /path/to/mt-config.cgi -o report.md
```

Perl バイナリを明示する場合:

```bash
ic-mt-hardening /path/to/mt --perl-bin /usr/bin/perl -o report.md
```

## チェック項目

- Movable Type ルート構造の確認
- `lib/MT.pm` または `mt.cgi` からのコアバージョン読み取り
- `mt-config.cgi` の主要設定確認
- `CGIPath` の HTTPS 利用確認
- `AdminScript` のデフォルト利用確認
- `DebugMode` の確認
- データベース接続設定の存在確認
- `TempDir` がアプリケーションルート配下にないかの確認
- `plugins/` 配下のプラグイン検出
- `themes/` 配下のテーマ検出
- ローカル JSON DB によるプラグイン/テーマ脆弱性マッチング
- NVD API による CVE 検索（明示指定時のみ）
- CGI ファイル、`mt-config.cgi`、`.env`、ツリー内 world-writable パスのパーミッション検査
- Perl 実行環境の確認

## CVE 検索

`--cve-check` を指定すると、NVD API で Movable Type core、プラグイン、テーマに関係する CVE を検索します。

NVD API キーはコマンドラインに書かず、環境変数または `.env` に設定します。

```dotenv
NVD_API_KEY=your-api-key
```

`.env` はカレントディレクトリまたは対象 Movable Type ルートに置けます。別のファイルを使う場合は、コマンドライン引数ではなく `IC_MT_HARDENING_ENV_FILE` 環境変数で指定します。

```bash
ic-mt-hardening /path/to/mt --cve-check -o report.md
```

検索方法:

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-match cpe
ic-mt-hardening /path/to/mt --cve-check --cve-match keyword
ic-mt-hardening /path/to/mt --cve-check --cve-match both
```

デフォルトは `cpe` です。Movable Type core は組み込みの CPE テンプレートを使います。プラグインやテーマは CPE が安定して付いていないことがあるため、必要に応じて `--cve-map` で対応表を渡します。

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-map cve-map.json
```

`cve-map.json` の例:

```json
{
  "plugins": {
    "example-plugin": "cpe:2.3:a:example:example_plugin:{version}:*:*:*:*:movable_type:*:*"
  },
  "themes": {
    "example-theme": "cpe:2.3:a:example:example_theme:{version}:*:*:*:*:movable_type:*:*"
  }
}
```

`keyword` は `Movable Type <plugin name> <slug>` のようなキーワード検索です。誤検知や見逃しがあり得るため、レポートでは potential match として扱ってください。NVD へのリクエスト数も増えるため、必要な場合だけ `--cve-match keyword` または `--cve-match both` を指定してください。

NVD API のレスポンスをキャッシュする場合:

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-cache .cache/nvd-cves.json
```

NVD API のレート制限に配慮するため、API キーありではデフォルト 0.6 秒、API キーなしではデフォルト 6 秒の待機を入れます。変更する場合は `--nvd-delay` を指定します。

## レポート形式

Markdown と JSON を選べます。

```bash
ic-mt-hardening /path/to/mt --format markdown -o report.md
ic-mt-hardening /path/to/mt --format json -o report.json
```

JSON には `summary` と `findings` が含まれます。各 finding には `check`, `status`, `message`, `detail`, `path`, `remediation`, `evidence`, `source` が入ります。

## 脆弱性 DB

外部サービスの API キーに依存しないよう、脆弱性情報は任意のローカル JSON ファイルとして渡せます。

```bash
ic-mt-hardening /path/to/mt --vuln-db vuln-db.json -o report.md
```

形式:

```json
[
  {
    "type": "plugin",
    "slug": "example-plugin",
    "title": "Stored XSS in admin screen",
    "affected": "< 1.2.3",
    "fixed_in": "1.2.3",
    "severity": "high",
    "url": "https://example.com/advisory"
  }
]
```

`type` は `plugin` または `theme` を指定できます。`affected` は `*`, `< 1.2.3`, `<= 2.0.0`, `>= 1.0.0, < 1.1.0` のように指定できます。

`severity` は `critical`/`high` を `FAIL`、`medium`/`moderate`/`low` を `WARN`、その他を `INFO` として扱います。

## 終了コード

デフォルトでは `FAIL` がある場合に終了コード `1` を返します。

```bash
ic-mt-hardening /path/to/mt --fail-on warn
ic-mt-hardening /path/to/mt --fail-on never
```

## 注意点

このツールは運用状態の一次チェックを目的としています。Movable Type の構成やホスティング環境によって適切な権限や配置は異なります。レポートの `WARN` は、必ずしも即時の脆弱性ではなく、追加確認が必要なハードニングシグナルとして扱ってください。

ローカル脆弱性 DB は、指定した JSON に含まれる情報だけを検出します。網羅的な脆弱性診断には、最新の脆弱性フィードや商用/公開 API と組み合わせてください。

NVD API を利用する場合、このツールは NVD API のデータを利用しますが、NVD により承認または認証されたものではありません。CVE の keyword 検索は補助情報であり、最終判断には CVE の references、CPE、影響バージョン、修正版を確認してください。

## License

MIT

## Authors

- Info Circus,Inc (https://www.infocircus.jp/)
- incmplt (https://www.incmplt.net/)
