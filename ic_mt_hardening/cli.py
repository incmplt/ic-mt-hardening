from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import __version__


STATUSES = ("PASS", "INFO", "WARN", "FAIL")


@dataclass(frozen=True)
class Finding:
    check: str
    status: str
    message: str
    detail: str = ""
    path: str = ""
    remediation: str = ""
    evidence: str = ""
    source: str = "static"


@dataclass(frozen=True)
class Extension:
    kind: str
    slug: str
    name: str
    version: str
    path: Path


@dataclass(frozen=True)
class CveTarget:
    kind: str
    slug: str
    name: str
    version: str
    path: str = ""


@dataclass(frozen=True)
class DangerousFileRule:
    pattern: str
    status: str
    reason: str


DANGEROUS_FILE_RULES = (
    DangerousFileRule("mt-config.cgi~", "FAIL", "Movable Type config backup"),
    DangerousFileRule("mt-config.cgi.bak", "FAIL", "Movable Type config backup"),
    DangerousFileRule("mt-config.cgi.old", "FAIL", "Movable Type config backup"),
    DangerousFileRule("mt-config.cgi.orig", "FAIL", "Movable Type config backup"),
    DangerousFileRule("mt-config.cgi.save", "FAIL", "Movable Type config backup"),
    DangerousFileRule(".env~", "FAIL", "environment file backup"),
    DangerousFileRule(".env.bak", "FAIL", "environment file backup"),
    DangerousFileRule(".env.old", "FAIL", "environment file backup"),
    DangerousFileRule(".env.orig", "FAIL", "environment file backup"),
    DangerousFileRule(".env.save", "FAIL", "environment file backup"),
    DangerousFileRule(".env", "FAIL", "environment file"),
    DangerousFileRule("wp-config.php~", "FAIL", "WordPress config backup"),
    DangerousFileRule("wp-config.php.bak", "FAIL", "WordPress config backup"),
    DangerousFileRule("wp-config.php.old", "FAIL", "WordPress config backup"),
    DangerousFileRule("wp-config.php.orig", "FAIL", "WordPress config backup"),
    DangerousFileRule("wp-config.php.save", "FAIL", "WordPress config backup"),
    DangerousFileRule(".git/config", "FAIL", "Git metadata"),
    DangerousFileRule("*/.git/config", "FAIL", "Git metadata"),
    DangerousFileRule(".svn/entries", "FAIL", "Subversion metadata"),
    DangerousFileRule("*/.svn/entries", "FAIL", "Subversion metadata"),
    DangerousFileRule(".hg/hgrc", "FAIL", "Mercurial metadata"),
    DangerousFileRule("*/.hg/hgrc", "FAIL", "Mercurial metadata"),
    DangerousFileRule("*.sql", "FAIL", "database dump"),
    DangerousFileRule("*.sql.gz", "FAIL", "compressed database dump"),
    DangerousFileRule("*.sql.zip", "FAIL", "compressed database dump"),
    DangerousFileRule("readme.html", "WARN", "public documentation file"),
    DangerousFileRule("debug.log", "WARN", "debug log"),
    DangerousFileRule("error_log", "WARN", "web server error log"),
    DangerousFileRule("*.zip", "WARN", "archive file"),
    DangerousFileRule("*.tar", "WARN", "archive file"),
    DangerousFileRule("*.tar.gz", "WARN", "archive file"),
    DangerousFileRule("*.tgz", "WARN", "archive file"),
    DangerousFileRule("*.7z", "WARN", "archive file"),
    DangerousFileRule("*.rar", "WARN", "archive file"),
    DangerousFileRule("*.bak", "WARN", "backup file"),
    DangerousFileRule("*.old", "WARN", "backup file"),
    DangerousFileRule("*.orig", "WARN", "backup file"),
    DangerousFileRule("*.save", "WARN", "backup file"),
    DangerousFileRule("*~", "WARN", "editor backup file"),
    DangerousFileRule("*.swp", "WARN", "editor swap file"),
    DangerousFileRule("*.tmp", "WARN", "temporary file"),
)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.mt_root.resolve()
    document_root = args.document_root.resolve() if args.document_root else root
    load_env_files(root)

    findings: list[Finding] = []
    findings.extend(check_movable_type_root(root))

    if any(f.check == "mt-root" and f.status == "FAIL" for f in findings):
        report = render_report(root, findings, args.format)
        write_report(args.output, report)
        return exit_code(args.fail_on, findings)

    core_version = read_movable_type_version(root)
    findings.extend(check_platform(root))
    findings.extend(check_core_version(root, core_version))

    config_path = args.mt_config.resolve() if args.mt_config else find_mt_config(root)
    findings.extend(check_mt_config(root, config_path))

    plugins = discover_extensions(root / "plugins", "plugin")
    themes = discover_extensions(root / "themes", "theme")
    findings.extend(check_extensions(plugins, "plugin", args.vuln_db))
    findings.extend(check_plugin_activation(plugins, config_path))
    findings.extend(check_extensions(themes, "theme", args.vuln_db))

    if args.cve_check:
        findings.extend(
            check_cves(
                root=root,
                core_version=core_version,
                extensions=[*plugins, *themes],
                cve_map_path=args.cve_map,
                cve_match=args.cve_match,
                cve_max_results=args.cve_max_results,
                cve_max_keyword_targets=args.cve_max_keyword_targets,
                cve_cache_path=args.cve_cache,
                nvd_api_key=os.environ.get("NVD_API_KEY", ""),
                nvd_delay=args.nvd_delay,
                timeout=args.timeout,
            )
        )

    findings.extend(check_cgi_permissions(root))
    findings.extend(
        check_dangerous_files(
            scan_root=document_root,
            max_findings=args.max_dangerous_file_findings,
            mt_root=root,
        )
    )
    findings.extend(check_permissions(root, config_path, args.max_permission_findings))
    findings.extend(check_perl_runtime(args.perl_bin, args.timeout))

    report = render_report(root, findings, args.format)
    write_report(args.output, report)
    return exit_code(args.fail_on, findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ic-mt-hardening",
        description="Check a local Movable Type installation and output a security report.",
    )
    parser.add_argument("mt_root", type=Path, help="Path to the Movable Type application root.")
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file.")
    parser.add_argument(
        "--document-root",
        type=Path,
        help=(
            "Path to the web server DocumentRoot for dangerous-file checks. "
            "Defaults to the Movable Type root."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report output format. Default: markdown.",
    )
    parser.add_argument("--mt-config", type=Path, help="Path to mt-config.cgi.")
    parser.add_argument("--perl-bin", default="perl", help="Perl binary. Default: perl.")
    parser.add_argument(
        "--vuln-db",
        type=Path,
        help="Local JSON vulnerability database for core/plugin/theme checks.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Network/process timeout in seconds. Default: 8.",
    )
    parser.add_argument(
        "--cve-check",
        action="store_true",
        help="Search NVD for CVEs related to Movable Type core, plugins, and themes.",
    )
    parser.add_argument(
        "--cve-match",
        choices=("cpe", "keyword", "both"),
        default="cpe",
        help="CVE search strategy. Keyword search can be noisy. Default: cpe.",
    )
    parser.add_argument(
        "--cve-map",
        type=Path,
        help="JSON file mapping Movable Type core/plugins/themes to CPE names or templates.",
    )
    parser.add_argument("--cve-cache", type=Path, help="Optional JSON cache for NVD API responses.")
    parser.add_argument(
        "--cve-max-results",
        type=int,
        default=20,
        help="Maximum NVD CVE records to request per target. Default: 20.",
    )
    parser.add_argument(
        "--cve-max-keyword-targets",
        type=int,
        default=20,
        help="Maximum plugin/theme targets searched with keyword fallback. Default: 20.",
    )
    parser.add_argument(
        "--nvd-delay",
        type=float,
        help="Delay between NVD API requests. Default: 0.6s with API key, 6.0s without.",
    )
    parser.add_argument(
        "--max-permission-findings",
        type=int,
        default=25,
        help="Maximum individual permission paths shown in the report. Default: 25.",
    )
    parser.add_argument(
        "--max-dangerous-file-findings",
        type=int,
        default=25,
        help="Maximum dangerous file paths shown in the report. Default: 25.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("fail", "warn", "never"),
        default="fail",
        help="Exit non-zero when findings reach this level. Default: fail.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_env_files(root: Path) -> None:
    candidates: list[Path] = []
    configured = os.environ.get("IC_MT_HARDENING_ENV_FILE", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend([Path.cwd() / ".env", root / ".env"])

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_env_file(resolved)


def load_env_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in os.environ:
            continue
        os.environ[key] = parse_env_value(value)


def parse_env_value(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value.split(" #", 1)[0].strip()


def check_movable_type_root(root: Path) -> list[Finding]:
    if not root.exists():
        return [Finding("mt-root", "FAIL", "Movable Type root does not exist.", path=str(root))]

    mt_cgi = root / "mt.cgi"
    mt_pm = root / "lib" / "MT.pm"
    if not mt_cgi.exists() and not mt_pm.exists():
        return [
            Finding(
                "mt-root",
                "FAIL",
                "Target does not look like a Movable Type application root.",
                "Expected mt.cgi and/or lib/MT.pm.",
                path=str(root),
            )
        ]

    missing = [path.relative_to(root).as_posix() for path in (mt_cgi, mt_pm) if not path.exists()]
    if missing:
        return [
            Finding(
                "mt-root",
                "WARN",
                "Movable Type root was partially detected.",
                "Missing: " + ", ".join(missing),
                path=str(root),
            )
        ]
    return [Finding("mt-root", "PASS", "Movable Type root structure was detected.", path=str(root))]


def check_core_version(root: Path, version: str) -> list[Finding]:
    version_file = root / "lib" / "MT.pm"
    if not version:
        return [
            Finding(
                "core-version",
                "WARN",
                "Could not read Movable Type core version.",
                path=str(version_file),
            )
        ]
    return [
        Finding(
            "core-version",
            "INFO",
            f"Installed Movable Type version: {version}",
            path=str(version_file),
        )
    ]


def check_platform(root: Path) -> list[Finding]:
    signals = find_powercms_signals(root)
    if signals:
        return [
            Finding(
                "platform",
                "INFO",
                "PowerCMS-compatible Movable Type installation signal was detected.",
                "\n".join(signals),
                path=str(root),
            )
        ]
    return [
        Finding(
            "platform",
            "INFO",
            "No PowerCMS-specific signal was detected; treating target as Movable Type-compatible.",
            path=str(root),
        )
    ]


def find_powercms_signals(root: Path) -> list[str]:
    search_roots = [
        root / "plugins",
        root / "addons",
        root / "lib",
        root / "mt-static" / "plugins",
    ]
    signals: list[str] = []
    for base in search_roots:
        if not base.exists() or not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if "powercms" in relative.lower():
                signals.append(relative + ("/" if path.is_dir() else ""))
            if len(signals) >= 10:
                return signals
    return signals


def read_movable_type_version(root: Path) -> str:
    candidates = [root / "lib" / "MT.pm", root / "mt.cgi"]
    patterns = [
        re.compile(r"\$VERSION\s*=\s*['\"]([^'\"]+)['\"]"),
        re.compile(r"\$MT::VERSION\s*=\s*['\"]([^'\"]+)['\"]"),
    ]
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(1).strip()
    return ""


def find_mt_config(root: Path) -> Path | None:
    for candidate in (root / "mt-config.cgi", root.parent / "mt-config.cgi"):
        if candidate.exists():
            return candidate
    return None


def check_mt_config(root: Path, config_path: Path | None) -> list[Finding]:
    if config_path is None:
        return [
            Finding(
                "mt-config",
                "FAIL",
                "mt-config.cgi was not found in the Movable Type root or its parent directory.",
                remediation="Confirm the target path or restore mt-config.cgi.",
            )
        ]

    values = parse_mt_config_file(config_path)
    return evaluate_mt_config_values(root, values, config_path)


def parse_mt_config_file(path: Path) -> dict[str, list[str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}

    values: dict[str, list[str]] = {}
    for raw_line in lines:
        line = strip_inline_comment(raw_line).strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        key = parts[0].strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            continue
        value = parse_config_value(parts[1] if len(parts) > 1 else "")
        values.setdefault(key.lower(), []).append(value)
    return values


def strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def parse_config_value(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def config_value(values: dict[str, list[str]], key: str) -> str:
    entries = values.get(key.lower()) or []
    return entries[-1] if entries else ""


def evaluate_mt_config_values(
    root: Path, values: dict[str, list[str]], config_path: Path
) -> list[Finding]:
    findings: list[Finding] = [
        Finding("mt-config", "PASS", "mt-config.cgi was found.", path=str(config_path))
    ]

    cgi_path = config_value(values, "CGIPath")
    if cgi_path:
        status = "WARN" if cgi_path.lower().startswith("http://") else "PASS"
        findings.append(
            Finding(
                "mt-config",
                status,
                "CGIPath is configured." if status == "PASS" else "CGIPath uses plain HTTP.",
                cgi_path,
                path=str(config_path),
                remediation="Use an HTTPS CGIPath on production sites." if status == "WARN" else "",
            )
        )
    else:
        findings.append(
            Finding(
                "mt-config",
                "WARN",
                "CGIPath is not configured.",
                path=str(config_path),
            )
        )

    static_web_path = config_value(values, "StaticWebPath")
    static_file_path = config_value(values, "StaticFilePath")
    if static_web_path or static_file_path or (root / "mt-static").exists():
        findings.append(Finding("mt-config", "PASS", "Static asset path is configured or present."))
    else:
        findings.append(
            Finding(
                "mt-config",
                "WARN",
                "Static asset path was not detected.",
                "Set StaticWebPath/StaticFilePath or confirm mt-static placement.",
                path=str(config_path),
            )
        )

    admin_script = config_value(values, "AdminScript")
    if not admin_script:
        findings.append(
            Finding(
                "mt-config",
                "INFO",
                "AdminScript is not configured.",
                "The default admin entry point is usually mt.cgi.",
                remediation="Consider renaming the admin CGI and setting AdminScript where supported.",
                path=str(config_path),
            )
        )
    elif admin_script == "mt.cgi":
        findings.append(
            Finding(
                "mt-config",
                "WARN",
                "AdminScript is set to the default mt.cgi.",
                remediation="Use a less predictable admin CGI name where supported.",
                path=str(config_path),
            )
        )
    else:
        findings.append(Finding("mt-config", "PASS", "AdminScript is customized.", path=str(config_path)))

    debug_mode = config_value(values, "DebugMode")
    if debug_mode and normalize_bool(debug_mode) == "on":
        findings.append(
            Finding(
                "mt-config",
                "WARN",
                "DebugMode appears to be enabled.",
                debug_mode,
                remediation="Disable DebugMode on production sites.",
                path=str(config_path),
            )
        )
    elif debug_mode:
        findings.append(Finding("mt-config", "PASS", "DebugMode is disabled.", path=str(config_path)))
    else:
        findings.append(Finding("mt-config", "INFO", "DebugMode is not configured.", path=str(config_path)))

    object_driver = config_value(values, "ObjectDriver")
    database = config_value(values, "Database")
    db_user = config_value(values, "DBUser")
    db_password = config_value(values, "DBPassword")
    if object_driver:
        findings.append(Finding("mt-config", "PASS", f"ObjectDriver is configured: {object_driver}."))
    else:
        findings.append(Finding("mt-config", "INFO", "ObjectDriver is not configured."))
    if not database:
        findings.append(Finding("mt-config", "WARN", "Database is not configured.", path=str(config_path)))
    if not db_user:
        findings.append(Finding("mt-config", "WARN", "DBUser is not configured.", path=str(config_path)))
    if db_password == "":
        findings.append(
            Finding(
                "mt-config",
                "FAIL",
                "DBPassword is empty or not configured.",
                remediation="Use a strong database password and a least-privilege database account.",
                path=str(config_path),
            )
        )
    else:
        findings.append(Finding("mt-config", "PASS", "DBPassword is configured.", path=str(config_path)))

    temp_dir = config_value(values, "TempDir")
    if temp_dir and is_path_under(temp_dir, root):
        findings.append(
            Finding(
                "mt-config",
                "WARN",
                "TempDir appears to be inside the Movable Type application root.",
                temp_dir,
                remediation="Place temporary files outside the web-accessible application tree.",
                path=str(config_path),
            )
        )

    return findings


def is_path_under(value: str, root: Path) -> bool:
    if not value or value.startswith(("http://", "https://")):
        return False
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def discover_extensions(base: Path, kind: str) -> list[Extension]:
    if not base.exists() or not base.is_dir():
        return []

    extensions: list[Extension] = []
    for path in sorted(item for item in base.iterdir() if item.is_dir()):
        metadata = read_extension_metadata(path)
        slug = metadata.get("id") or normalize_slug(path.name)
        name = metadata.get("name") or path.name
        version = metadata.get("version") or ""
        extensions.append(Extension(kind=kind, slug=slug, name=name, version=version, path=path))
    return extensions


def read_extension_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    candidates = [
        path / "config.yaml",
        path / "config.yml",
        path / "plugin.yaml",
        path / "plugin.yml",
        path / "theme.yaml",
        path / "theme.yml",
    ]
    candidates.extend(sorted(path.glob("*.pl")))

    for candidate in candidates:
        if not candidate.exists() or not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        metadata.update(parse_metadata_text(text))
        if metadata:
            break
    return metadata


def parse_metadata_text(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    simple_patterns = {
        "id": re.compile(r"^\s*id\s*:\s*['\"]?([^'\"\n#]+)", re.IGNORECASE | re.MULTILINE),
        "name": re.compile(r"^\s*name\s*:\s*['\"]?([^'\"\n#]+)", re.IGNORECASE | re.MULTILINE),
        "version": re.compile(r"^\s*version\s*:\s*['\"]?([^'\"\n#]+)", re.IGNORECASE | re.MULTILINE),
    }
    for key, pattern in simple_patterns.items():
        match = pattern.search(text)
        if match:
            metadata[key] = match.group(1).strip()

    perl_name = re.search(r"name\s*=>\s*['\"]([^'\"]+)['\"]", text)
    perl_version = re.search(r"version\s*=>\s*['\"]([^'\"]+)['\"]", text)
    if perl_name and "name" not in metadata:
        metadata["name"] = perl_name.group(1).strip()
    if perl_version and "version" not in metadata:
        metadata["version"] = perl_version.group(1).strip()
    return metadata


def check_extensions(extensions: list[Extension], kind: str, vuln_db_path: Path | None) -> list[Finding]:
    check = "plugins" if kind == "plugin" else "themes"
    if not extensions:
        return [Finding(check, "INFO", f"No Movable Type {kind}s were detected.")]

    findings = [
        Finding(check, "INFO", f"Detected {len(extensions)} Movable Type {kind}(s)."),
    ]
    for extension in extensions:
        version_text = extension.version or "unknown version"
        findings.append(
            Finding(
                f"{kind}-inventory",
                "INFO",
                f"{extension.name}: {version_text}",
                path=str(extension.path),
            )
        )

    if vuln_db_path:
        findings.extend(check_vulnerability_db(extensions, vuln_db_path, kind))
    return findings


def check_plugin_activation(plugins: list[Extension], config_path: Path | None) -> list[Finding]:
    if not plugins:
        return []
    if config_path is None:
        return [
            Finding(
                "plugin-activation",
                "WARN",
                "Plugin activation state could not be checked because mt-config.cgi was not found.",
            )
        ]

    values = parse_mt_config_file(config_path)
    switches = parse_plugin_switches(values)
    if not switches:
        return [
            Finding(
                "plugin-activation",
                "INFO",
                "No PluginSwitch entries were found; detected plugins are not disabled in mt-config.cgi.",
                path=str(config_path),
            )
        ]

    findings: list[Finding] = []
    for plugin in plugins:
        state = plugin_switch_state(plugin, switches)
        if state == "off":
            findings.append(
                Finding(
                    "plugin-activation",
                    "WARN",
                    f"{plugin.name} appears to be disabled by PluginSwitch.",
                    path=str(plugin.path),
                    remediation="Confirm whether this plugin should be enabled for the target site.",
                )
            )
        elif state == "on":
            findings.append(
                Finding(
                    "plugin-activation",
                    "PASS",
                    f"{plugin.name} is enabled by PluginSwitch.",
                    path=str(plugin.path),
                )
            )
        else:
            findings.append(
                Finding(
                    "plugin-activation",
                    "INFO",
                    f"{plugin.name} has no PluginSwitch override.",
                    path=str(plugin.path),
                )
            )
    return findings


def parse_plugin_switches(values: dict[str, list[str]]) -> dict[str, str]:
    switches: dict[str, str] = {}
    for entry in values.get("pluginswitch", []):
        parts = entry.split()
        if len(parts) < 2:
            continue
        plugin_name = " ".join(parts[:-1])
        state = normalize_bool(parts[-1])
        if state in {"on", "off"}:
            switches[normalize_slug(plugin_name)] = state
    return switches


def plugin_switch_state(plugin: Extension, switches: dict[str, str]) -> str:
    candidates = {
        normalize_slug(plugin.slug),
        normalize_slug(plugin.name),
        normalize_slug(plugin.path.name),
    }
    for candidate in candidates:
        if candidate in switches:
            return switches[candidate]
    return ""


def check_vulnerability_db(
    extensions: Iterable[Extension], vuln_db_path: Path, kind: str
) -> list[Finding]:
    records, error = load_vulnerability_records(vuln_db_path)
    if error:
        return [Finding("vulnerability-db", "WARN", "Could not load vulnerability database.", error)]

    findings: list[Finding] = []
    by_slug = {extension.slug: extension for extension in extensions}
    by_name = {normalize_slug(extension.name): extension for extension in extensions}
    for record in records:
        if str(record.get("type", kind)).lower() not in {kind, f"{kind}s"}:
            continue
        slug = normalize_slug(str(record.get("slug") or record.get("name") or ""))
        extension = by_slug.get(slug) or by_name.get(slug)
        if extension is None:
            continue
        affected = str(record.get("affected") or "*")
        if not version_matches(extension.version, affected):
            continue
        severity = str(record.get("severity") or "").lower()
        status = severity_to_status(severity)
        fixed_in = str(record.get("fixed_in") or "")
        title = str(record.get("title") or "Known vulnerability")
        remediation = f"Update {extension.name}"
        if fixed_in:
            remediation += f" to {fixed_in} or later"
        findings.append(
            Finding(
                "vulnerability",
                status,
                f"{extension.name}: {title}",
                f"affected: {affected}; installed: {extension.version or 'unknown'}",
                path=str(extension.path),
                remediation=remediation + ".",
                evidence=json.dumps(record, ensure_ascii=False, sort_keys=True),
                source="local-db",
            )
        )
    if not findings:
        findings.append(Finding("vulnerability-db", "PASS", "No local vulnerability DB matches found."))
    return findings


def load_vulnerability_records(path: Path) -> tuple[list[dict[str, object]], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [], str(exc)
    except json.JSONDecodeError as exc:
        return [], f"Invalid JSON: {exc}"
    if not isinstance(payload, list):
        return [], "Vulnerability database must be a JSON array."
    return [item for item in payload if isinstance(item, dict)], ""


def check_cves(
    root: Path,
    core_version: str,
    extensions: list[Extension],
    cve_map_path: Path | None,
    cve_match: str,
    cve_max_results: int,
    cve_max_keyword_targets: int,
    cve_cache_path: Path | None,
    nvd_api_key: str,
    nvd_delay: float | None,
    timeout: float,
) -> list[Finding]:
    cache = load_json_cache(cve_cache_path)
    cve_map, map_error = load_cve_map(cve_map_path)
    findings: list[Finding] = []
    if map_error:
        findings.append(Finding("cve-map", "WARN", "Could not load CVE map.", map_error))

    targets = build_cve_targets(root, core_version, extensions)
    if not targets:
        return [Finding("cve", "INFO", "No CVE targets were detected.")]

    delay = nvd_delay if nvd_delay is not None else (0.6 if nvd_api_key else 6.0)
    keyword_count = 0
    transient_errors = 0
    searched = 0
    cve_findings: list[Finding] = []

    for target in targets:
        queries = build_nvd_queries(target, cve_map, cve_match, cve_max_results)
        if any("keywordSearch" in query for query in queries):
            if target.kind != "core":
                keyword_count += 1
            if keyword_count > cve_max_keyword_targets:
                findings.append(
                    Finding(
                        "cve-search",
                        "WARN",
                        "Skipped remaining keyword CVE searches after reaching the configured limit.",
                    )
                )
                break

        for query in queries:
            searched += 1
            response, error, from_cache = fetch_nvd_cves(
                query, nvd_api_key, timeout, cache, cve_cache_path
            )
            if response is None:
                transient_errors += 1
                findings.append(
                    Finding("cve-search", "WARN", "Could not complete NVD CVE search.", error)
                )
                if transient_errors >= 3:
                    findings.append(
                        Finding(
                            "cve-search",
                            "WARN",
                            "Stopped NVD CVE search after repeated transient errors.",
                        )
                    )
                    return findings + cve_findings
                continue
            transient_errors = 0
            cve_findings.extend(render_cve_findings(response, target, query, from_cache))
            if delay > 0 and not from_cache:
                time.sleep(delay)

    if cve_findings:
        return findings + cve_findings
    if searched:
        findings.append(Finding("cve", "PASS", "No NVD CVE matches found."))
    else:
        findings.append(Finding("cve", "INFO", "No NVD CVE searches were run."))
    return findings


def build_cve_targets(root: Path, core_version: str, extensions: list[Extension]) -> list[CveTarget]:
    targets: list[CveTarget] = []
    if core_version:
        targets.append(CveTarget("core", "movable-type", "Movable Type", core_version, str(root)))
    for extension in extensions:
        targets.append(
            CveTarget(
                extension.kind,
                extension.slug,
                extension.name,
                extension.version,
                str(extension.path),
            )
        )
    return targets


def load_cve_map(path: Path | None) -> tuple[dict[str, Any], str]:
    default = {
        "core": {
            "movable-type": "cpe:2.3:a:sixapart:movable_type:{version}:*:*:*:*:*:*:*"
        }
    }
    if path is None:
        return default, ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return default, str(exc)
    except json.JSONDecodeError as exc:
        return default, f"Invalid JSON: {exc}"
    if not isinstance(payload, dict):
        return default, "CVE map must be a JSON object."
    merged = dict(default)
    merged.update(payload)
    return merged, ""


def build_nvd_queries(
    target: CveTarget, cve_map: dict[str, Any], cve_match: str, cve_max_results: int
) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    if cve_match in {"cpe", "both"}:
        cpe_name = lookup_cpe(target, cve_map)
        if cpe_name:
            queries.append({"cpeName": cpe_name, "resultsPerPage": str(cve_max_results)})

    if cve_match in {"keyword", "both"}:
        terms = ["Movable Type", target.name]
        if target.slug and normalize_slug(target.name) != target.slug:
            terms.append(target.slug)
        if target.version:
            terms.append(target.version)
        queries.append({"keywordSearch": " ".join(terms), "resultsPerPage": str(cve_max_results)})
    return queries


def lookup_cpe(target: CveTarget, cve_map: dict[str, Any]) -> str:
    candidates: list[Any] = []
    for section_name in (target.kind, f"{target.kind}s"):
        section = cve_map.get(section_name)
        if isinstance(section, dict):
            candidates.extend([section.get(target.slug), section.get(normalize_slug(target.name))])
        elif isinstance(section, str) and target.kind == "core":
            candidates.append(section)
    for candidate in candidates:
        if isinstance(candidate, str) and candidate:
            return candidate.format(version=target.version or "*", slug=target.slug, name=target.name)
    return ""


def fetch_nvd_cves(
    params: dict[str, str],
    nvd_api_key: str,
    timeout: float,
    cache: dict[str, object],
    cache_path: Path | None,
) -> tuple[dict[str, object] | None, str, bool]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    if url in cache and isinstance(cache[url], dict):
        return cache[url], "", True

    request = urllib.request.Request(url)
    if nvd_api_key:
        request.add_header("apiKey", nvd_api_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None, f"NVD API HTTP {exc.code}: {exc.reason}", False
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return None, f"NVD API error: {exc}", False

    if isinstance(payload, dict):
        cache[url] = payload
        save_json_cache(cache_path, cache)
        return payload, "", False
    return None, "NVD API returned an unexpected payload.", False


def render_cve_findings(
    response: dict[str, object], target: CveTarget, query: dict[str, str], from_cache: bool
) -> list[Finding]:
    vulnerabilities = response.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    source = "nvd:cpe" if "cpeName" in query else "nvd:keyword"
    if from_cache:
        source += ":cache"
    findings: list[Finding] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "CVE")
        severity, score = extract_cve_severity(cve)
        status = severity_to_status(severity)
        description = extract_cve_description(cve)
        detail = f"{severity.upper() if severity else 'UNKNOWN'}"
        if score:
            detail += f" score {score}"
        if description:
            detail += f": {description}"
        findings.append(
            Finding(
                "cve",
                status,
                f"{cve_id} may affect {target.name}.",
                detail,
                path=target.path,
                remediation="Review the CVE references, affected versions, and vendor advisories.",
                evidence=json.dumps(
                    {
                        "id": cve_id,
                        "target": asdict(target),
                        "query": query,
                        "references": extract_cve_references(cve),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                source=source,
            )
        )
    return findings


def extract_cve_severity(cve: dict[str, object]) -> tuple[str, str]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return "", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0]
        if not isinstance(first, dict):
            continue
        cvss_data = first.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        severity = str(first.get("baseSeverity") or cvss_data.get("baseSeverity") or "")
        score = str(cvss_data.get("baseScore") or "")
        return severity.lower(), score
    return "", ""


def extract_cve_description(cve: dict[str, object]) -> str:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value") or "")[:500]
    return ""


def extract_cve_references(cve: dict[str, object]) -> list[str]:
    refs = cve.get("references")
    if not isinstance(refs, list):
        return []
    urls: list[str] = []
    for ref in refs[:10]:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            urls.append(ref["url"])
    return urls


def load_json_cache(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_json_cache(path: Path | None, cache: dict[str, object]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        return


def check_cgi_permissions(root: Path) -> list[Finding]:
    cgi_files = sorted(root.glob("*.cgi"))
    if not cgi_files:
        return [Finding("cgi-permissions", "WARN", "No CGI files were detected in the MT root.")]

    findings: list[Finding] = []
    for path in cgi_files:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            findings.append(Finding("cgi-permissions", "WARN", "Could not inspect CGI file.", str(exc), path=str(path)))
            continue
        mode_text = oct(mode)
        if mode & stat.S_IWOTH:
            findings.append(
                Finding(
                    "cgi-permissions",
                    "FAIL",
                    f"{path.name} is world-writable.",
                    mode_text,
                    path=str(path),
                    remediation="Remove group/other write permissions from CGI scripts.",
                )
            )
        elif mode & stat.S_IWGRP:
            findings.append(
                Finding(
                    "cgi-permissions",
                    "WARN",
                    f"{path.name} is group-writable.",
                    mode_text,
                    path=str(path),
                    remediation="Use the least permissive mode supported by the web server.",
                )
            )
        elif not mode & stat.S_IXUSR:
            findings.append(
                Finding(
                    "cgi-permissions",
                    "WARN",
                    f"{path.name} is not owner-executable.",
                    mode_text,
                    path=str(path),
                )
            )
        else:
            findings.append(Finding("cgi-permissions", "PASS", f"{path.name} mode is {mode_text}.", path=str(path)))
    return findings


def check_dangerous_files(scan_root: Path, max_findings: int, mt_root: Path | None = None) -> list[Finding]:
    if not scan_root.exists():
        return [
            Finding(
                "dangerous-files",
                "WARN",
                "Dangerous file scan root does not exist.",
                path=str(scan_root),
            )
        ]
    if not scan_root.is_dir():
        return [
            Finding(
                "dangerous-files",
                "WARN",
                "Dangerous file scan root is not a directory.",
                path=str(scan_root),
            )
        ]

    limit = max(max_findings, 0)
    matches: dict[str, list[str]] = {"FAIL": [], "WARN": []}
    counts: dict[str, int] = {"FAIL": 0, "WARN": 0}

    for path in scan_root.rglob("*"):
        try:
            if not (path.is_file() or path.is_symlink()):
                continue
        except OSError:
            continue

        try:
            relative_path = path.relative_to(scan_root).as_posix()
        except ValueError:
            continue
        rule = match_dangerous_file(relative_path)
        if rule is None:
            continue
        counts[rule.status] += 1
        if len(matches[rule.status]) < limit:
            matches[rule.status].append(f"{relative_path} ({rule.reason})")

    findings: list[Finding] = []
    if counts["FAIL"]:
        detail = render_dangerous_file_detail(matches["FAIL"], counts["FAIL"])
        findings.append(
            Finding(
                "dangerous-files",
                "FAIL",
                "Potentially sensitive files were found in the web-accessible tree.",
                detail,
                path=str(scan_root),
                remediation=(
                    "Remove these files from the web-accessible tree or move "
                    "them outside the document root."
                ),
            )
        )
    if counts["WARN"]:
        detail = render_dangerous_file_detail(matches["WARN"], counts["WARN"])
        findings.append(
            Finding(
                "dangerous-files",
                "WARN",
                "Backup, archive, debug, or temporary files were found.",
                detail,
                path=str(scan_root),
                remediation=(
                    "Confirm these files are not publicly accessible, or remove them from "
                    "the document root."
                ),
            )
        )
    if findings:
        if mt_root is not None and scan_root != mt_root:
            findings.append(
                Finding(
                    "dangerous-files",
                    "INFO",
                    "Dangerous file scan used a separate DocumentRoot.",
                    f"DocumentRoot: {scan_root}\nMovable Type root: {mt_root}",
                    path=str(scan_root),
                )
            )
        return findings
    message = "No dangerous backup, archive, debug, or temporary files were found."
    detail = ""
    if mt_root is not None and scan_root != mt_root:
        detail = f"DocumentRoot: {scan_root}\nMovable Type root: {mt_root}"
    return [
        Finding(
            "dangerous-files",
            "PASS",
            message,
            detail,
            path=str(scan_root),
        )
    ]


def render_dangerous_file_detail(paths: list[str], total_count: int) -> str:
    lines = list(paths)
    omitted = total_count - len(paths)
    if omitted > 0:
        lines.append(
            f"{omitted} additional match(es) omitted; increase --max-dangerous-file-findings."
        )
    return "\n".join(lines)


def match_dangerous_file(relative_path: str) -> DangerousFileRule | None:
    normalized = relative_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    for rule in DANGEROUS_FILE_RULES:
        pattern = rule.pattern.lower()
        target = normalized if "/" in pattern else name
        if fnmatch.fnmatchcase(target, pattern):
            return rule
    return None


def check_permissions(
    root: Path, config_path: Path | None, max_permission_findings: int
) -> list[Finding]:
    findings: list[Finding] = []
    sensitive_paths = [path for path in [config_path, root / ".env"] if path is not None and path.exists()]
    for path in sensitive_paths:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            findings.append(Finding("permissions", "WARN", "Could not inspect sensitive file.", str(exc), path=str(path)))
            continue
        mode_text = oct(mode)
        if mode & stat.S_IWOTH:
            findings.append(
                Finding(
                    "permissions",
                    "FAIL",
                    f"{path.name} is world-writable.",
                    mode_text,
                    path=str(path),
                    remediation="Remove write permissions for group and other users.",
                )
            )
        elif mode & stat.S_IROTH:
            findings.append(
                Finding(
                    "permissions",
                    "WARN",
                    f"{path.name} is readable by other users.",
                    mode_text,
                    path=str(path),
                    remediation="Restrict configuration files to the web server user/group where possible.",
                )
            )
        else:
            findings.append(Finding("permissions", "PASS", f"{path.name} mode is {mode_text}.", path=str(path)))

    bad_paths: list[str] = []
    for path in root.rglob("*"):
        if len(bad_paths) >= max_permission_findings:
            break
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            bad_paths.append(f"{path.relative_to(root).as_posix()} ({oct(mode)})")

    if bad_paths:
        findings.append(
            Finding(
                "permissions",
                "FAIL",
                "World-writable files or directories were found.",
                "\n".join(bad_paths),
                path=str(root),
                remediation="Remove other-write permissions from the listed paths.",
            )
        )
    else:
        findings.append(Finding("permissions", "PASS", "No world-writable paths were found.", path=str(root)))
    return findings


def check_perl_runtime(perl_bin: str, timeout: float) -> list[Finding]:
    if os.sep not in perl_bin and shutil.which(perl_bin) is None:
        return [Finding("perl", "WARN", f"Perl binary was not found: {perl_bin}", source="perl")]
    try:
        completed = subprocess.run(
            [perl_bin, "-e", "print $^V"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [Finding("perl", "WARN", "Could not execute Perl runtime check.", str(exc), source="perl")]
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
        return [Finding("perl", "WARN", "Perl runtime check failed.", detail, source="perl")]
    return [Finding("perl", "INFO", f"Perl runtime: {completed.stdout.strip()}", source="perl")]


def render_report(root: Path, findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return render_json_report(root, findings)
    return render_markdown_report(root, findings)


def render_json_report(root: Path, findings: list[Finding]) -> str:
    payload = {
        "tool": {"name": "ic-mt-hardening", "version": __version__},
        "target": str(root),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "summary": summarize_findings(findings),
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_markdown_report(root: Path, findings: list[Finding]) -> str:
    summary = summarize_findings(findings)
    lines = [
        "# Movable Type Hardening Report",
        "",
        f"- Target: `{root}`",
        f"- Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}",
        "- Summary: "
        + ", ".join(f"{status}={summary.get(status, 0)}" for status in ("FAIL", "WARN", "INFO", "PASS")),
        "",
        "## Findings",
        "",
        "| Status | Check | Message | Path |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    escape_md(finding.status),
                    escape_md(finding.check),
                    escape_md(finding.message),
                    escape_md(finding.path),
                ]
            )
            + " |"
        )
    detailed = [
        finding
        for finding in findings
        if finding.detail or finding.remediation or finding.evidence or finding.source != "static"
    ]
    if detailed:
        lines.extend(["", "## Details", ""])
        for index, finding in enumerate(detailed, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.status} {finding.check}",
                    "",
                    finding.message,
                ]
            )
            if finding.detail:
                lines.extend(["", "Detail:", "", "```text", finding.detail, "```"])
            if finding.remediation:
                lines.extend(["", f"Remediation: {finding.remediation}"])
            if finding.source != "static":
                lines.extend(["", f"Source: `{finding.source}`"])
            if finding.evidence:
                lines.extend(["", "Evidence:", "", "```json", finding.evidence, "```"])
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {status: 0 for status in STATUSES}
    for finding in findings:
        summary[finding.status] = summary.get(finding.status, 0) + 1
    return summary


def write_report(output: Path | None, report: str) -> None:
    if output:
        output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)


def exit_code(fail_on: str, findings: Iterable[Finding]) -> int:
    statuses = {finding.status for finding in findings}
    if fail_on == "never":
        return 0
    if "FAIL" in statuses:
        return 1
    if fail_on == "warn" and "WARN" in statuses:
        return 1
    return 0


def escape_md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def normalize_bool(value: str) -> str:
    normalized = value.strip().strip("'\"").lower()
    if normalized in {"1", "true", "yes", "on"}:
        return "on"
    if normalized in {"0", "false", "no", "off"}:
        return "off"
    return normalized


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return slug.strip("-")


def severity_to_status(severity: str) -> str:
    severity = severity.lower()
    if severity in {"critical", "high"}:
        return "FAIL"
    if severity in {"medium", "moderate", "low"}:
        return "WARN"
    return "INFO"


def version_matches(version: str, requirement: str) -> bool:
    requirement = requirement.strip()
    if not requirement or requirement == "*":
        return True
    if not version:
        return True
    clauses = [clause.strip() for clause in requirement.split(",") if clause.strip()]
    for clause in clauses:
        match = re.fullmatch(r"(<=|>=|<|>|==|=)?\s*(.+)", clause)
        if not match:
            return False
        operator = match.group(1) or "=="
        wanted = match.group(2).strip()
        comparison = compare_versions(version, wanted)
        if operator in {"=", "=="} and comparison != 0:
            return False
        if operator == "<" and comparison >= 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == ">=" and comparison < 0:
            return False
    return True


def compare_versions(left: str, right: str) -> int:
    left_key = version_key(left)
    right_key = version_key(right)
    max_len = max(len(left_key), len(right_key))
    left_key.extend([0] * (max_len - len(left_key)))
    right_key.extend([0] * (max_len - len(right_key)))
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def version_key(version: str) -> list[int]:
    parts = re.findall(r"\d+", version)
    return [int(part) for part in parts] if parts else [0]
