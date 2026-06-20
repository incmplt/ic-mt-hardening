# ic-mt-hardening

A CLI tool that checks Movable Type version, `mt-config.cgi`, plugins, themes, CGI/config file permissions, and the Perl runtime, then outputs a Markdown or JSON report.

The target is a local Movable Type application root on the same server. PowerCMS installations with a Movable Type-compatible layout can also be checked as MT-compatible roots. The tool runs with the Python standard library only.

## Usage

```bash
python -m ic_mt_hardening /path/to/mt -o report.md
```

To install and use it as a command:

```bash
pip install .
ic-mt-hardening /path/to/mt -o report.md
```

To output a JSON report:

```bash
ic-mt-hardening /path/to/mt --format json -o report.json
```

To specify `mt-config.cgi`:

```bash
ic-mt-hardening /path/to/mt --mt-config /path/to/mt-config.cgi -o report.md
```

To specify a Perl binary:

```bash
ic-mt-hardening /path/to/mt --perl-bin /usr/bin/perl -o report.md
```

For PowerCMS validation, pass the PowerCMS application root.

```bash
ic-mt-hardening /path/to/powercms --format json -o powercms-report.json
```

## Checks

- Movable Type root structure detection
- PowerCMS-like file/directory signal detection
- Core version detection from `lib/MT.pm` or `mt.cgi`
- Key `mt-config.cgi` setting checks
- HTTPS check for `CGIPath`
- Default `AdminScript` check
- `DebugMode` check
- Database connection setting presence
- `TempDir` placement check
- Plugin detection under `plugins/`
- Plugin enabled/disabled state checks from `PluginSwitch` entries in `mt-config.cgi`
- Theme detection under `themes/`
- Plugin/theme vulnerability matching with a local JSON database
- CVE search through the NVD API when explicitly enabled
- Dangerous file detection under the MT root or the DocumentRoot passed with `--document-root`
- Detection for files such as `.env`, `.git/config`, `readme.html`, `.sql`, `.zip`, `.bak`, `wp-config.php~`, and `debug.log`
- Permission checks for CGI files, `mt-config.cgi`, `.env`, and world-writable paths
- Perl runtime check

## CVE Search

When `--cve-check` is specified, the tool searches the NVD API for CVEs related to Movable Type core, plugins, and themes.

Do not put the NVD API key on the command line. Set it through an environment variable or `.env`.

```dotenv
NVD_API_KEY=your-api-key
```

`.env` can be placed in the current working directory or the target Movable Type root. To use another file, set the `IC_MT_HARDENING_ENV_FILE` environment variable instead of passing a command-line argument.

```bash
ic-mt-hardening /path/to/mt --cve-check -o report.md
```

Search strategies:

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-match cpe
ic-mt-hardening /path/to/mt --cve-check --cve-match keyword
ic-mt-hardening /path/to/mt --cve-check --cve-match both
```

The default is `cpe`. Movable Type core uses a built-in CPE template. Plugins and themes do not always have stable CPE coverage, so you can provide mappings with `--cve-map`.

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-map cve-map.json
```

Example `cve-map.json`:

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

`keyword` searches use terms such as `Movable Type <plugin name> <slug>`. Because keyword search can produce false positives or miss records, treat these results as potential matches. It also increases NVD request volume, so use `--cve-match keyword` or `--cve-match both` only when needed.

To cache NVD API responses:

```bash
ic-mt-hardening /path/to/mt --cve-check --cve-cache .cache/nvd-cves.json
```

To respect NVD API rate limits, the default delay is 0.6 seconds with an API key and 6 seconds without an API key. Use `--nvd-delay` to override this.

## Report Formats

Markdown and JSON are supported.

```bash
ic-mt-hardening /path/to/mt --format markdown -o report.md
ic-mt-hardening /path/to/mt --format json -o report.json
```

The JSON report contains `summary` and `findings`. Each finding includes `check`, `status`, `message`, `detail`, `path`, `remediation`, `evidence`, and `source`.

For PowerCMS compatibility validation, review the `platform` and `plugin-activation` findings. Plugins without a `PluginSwitch` entry are reported as `INFO` because they are not disabled in the config file.

## DocumentRoot Dangerous File Detection

The tool detects backup files, archives, debug logs, database dumps, and configuration backups left under the Movable Type root.

If Movable Type is installed below the DocumentRoot, such as `/var/www/html/hogehoge/mt/`, pass `--document-root` to scan the whole DocumentRoot.

```bash
ic-mt-hardening /var/www/html/hogehoge/mt --document-root /var/www/html -o report.md
```

Examples:

- `.env`
- `.git/config`
- `readme.html`
- `debug.log`
- `*.sql`
- `*.zip`
- `*.bak`
- `*~`
- `mt-config.cgi.bak`
- `wp-config.php~`

You can change the number of paths shown in the report.

```bash
ic-mt-hardening /path/to/mt --max-dangerous-file-findings 50 -o report.md
```

## Vulnerability Database

To avoid depending on an external service API key, vulnerability data can be supplied as a local JSON file.

```bash
ic-mt-hardening /path/to/mt --vuln-db vuln-db.json -o report.md
```

Format:

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

`type` can be `plugin` or `theme`. `affected` can be specified as `*`, `< 1.2.3`, `<= 2.0.0`, or `>= 1.0.0, < 1.1.0`.

`severity` values of `critical` or `high` are treated as `FAIL`; `medium`, `moderate`, or `low` are treated as `WARN`; all other values are treated as `INFO`.

## Exit Codes

By default, the command exits with status code `1` when any `FAIL` finding exists.

```bash
ic-mt-hardening /path/to/mt --fail-on warn
ic-mt-hardening /path/to/mt --fail-on never
```

## Notes

This tool is intended as an initial operational check. Appropriate permissions and placement can vary by Movable Type version and hosting environment. Treat `WARN` findings as hardening signals that require review, not always as direct vulnerabilities.

Local vulnerability matches are detected only when they are included in the supplied JSON database. For comprehensive vulnerability assessment, combine this tool with current vulnerability feeds or commercial/public APIs.

When using the NVD API, this product uses data from the NVD API but is not endorsed or certified by the NVD. CVE keyword search is supplemental; review CVE references, CPE data, affected versions, and fixed versions before making a final assessment.

## License

MIT

## Authors

- Info Circus,Inc (https://www.infocircus.jp/)
- incmplt (https://www.incmplt.net/)
