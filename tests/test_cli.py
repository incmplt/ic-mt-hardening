from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from ic_mt_hardening import cli


class CliTests(unittest.TestCase):
    def test_json_report_includes_mt_config_plugins_themes_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_movable_type_fixture(Path(tmp))

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--perl-bin",
                    "missing-perl-for-test",
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        checks = {finding["check"] for finding in report["findings"]}
        self.assertEqual(report["tool"]["name"], "ic-mt-hardening")
        self.assertIn("mt-root", checks)
        self.assertIn("core-version", checks)
        self.assertIn("mt-config", checks)
        self.assertIn("plugins", checks)
        self.assertIn("plugin-inventory", checks)
        self.assertIn("themes", checks)
        self.assertIn("theme-inventory", checks)
        self.assertIn("cgi-permissions", checks)
        self.assertIn("dangerous-files", checks)
        self.assertIn("permissions", checks)

    def test_config_checks_warn_for_http_default_admin_and_debug_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_movable_type_fixture(Path(tmp), insecure_config=True)

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--perl-bin",
                    "missing-perl-for-test",
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        warnings = [
            finding["message"]
            for finding in report["findings"]
            if finding["check"] == "mt-config" and finding["status"] == "WARN"
        ]
        self.assertIn("CGIPath uses plain HTTP.", warnings)
        self.assertIn("AdminScript is set to the default mt.cgi.", warnings)
        self.assertIn("DebugMode appears to be enabled.", warnings)

    def test_local_vulnerability_database_reports_matching_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = make_movable_type_fixture(base)
            vuln_db = base / "vuln-db.json"
            vuln_db.write_text(
                json.dumps(
                    [
                        {
                            "type": "plugin",
                            "slug": "example-plugin",
                            "title": "Stored XSS in plugin screen",
                            "affected": "< 1.2.0",
                            "fixed_in": "1.2.0",
                            "severity": "high",
                            "url": "https://example.test/advisory",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--vuln-db",
                    str(vuln_db),
                    "--perl-bin",
                    "missing-perl-for-test",
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        findings = report["findings"]
        self.assertTrue(
            any(
                finding["check"] == "vulnerability"
                and finding["status"] == "FAIL"
                and "Stored XSS" in finding["message"]
                for finding in findings
            )
        )

    def test_dangerous_files_report_sensitive_backups_and_debug_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_movable_type_fixture(Path(tmp))
            (root / "backup.sql").write_text("-- dump\n", encoding="utf-8")
            (root / "debug.log").write_text("debug output\n", encoding="utf-8")
            (root / "wp-config.php~").write_text("<?php\n", encoding="utf-8")
            (root / "readme.html").write_text("<h1>Readme</h1>\n", encoding="utf-8")

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--perl-bin",
                    "missing-perl-for-test",
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        findings = [
            finding for finding in report["findings"] if finding["check"] == "dangerous-files"
        ]
        self.assertTrue(
            any(
                finding["status"] == "FAIL"
                and "backup.sql" in finding["detail"]
                and "wp-config.php~" in finding["detail"]
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding["status"] == "WARN"
                and "debug.log" in finding["detail"]
                and "readme.html" in finding["detail"]
                for finding in findings
            )
        )

    def test_dangerous_files_can_scan_document_root_above_mt_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document_root = Path(tmp) / "html"
            mt_parent = document_root / "hogehoge"
            root = make_movable_type_fixture(mt_parent)
            (document_root / "backup.sql").write_text("-- dump\n", encoding="utf-8")
            (document_root / ".git").mkdir()
            (document_root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
            (document_root / "debug.log").write_text("debug output\n", encoding="utf-8")

            output = run_cli_capture(
                [
                    str(root),
                    "--document-root",
                    str(document_root),
                    "--format",
                    "json",
                    "--perl-bin",
                    "missing-perl-for-test",
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        findings = [
            finding for finding in report["findings"] if finding["check"] == "dangerous-files"
        ]
        self.assertTrue(
            any(
                finding["status"] == "FAIL"
                and "backup.sql" in finding["detail"]
                and ".git/config" in finding["detail"]
                and finding["path"] == str(document_root.resolve())
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding["status"] == "WARN" and "debug.log" in finding["detail"]
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding["status"] == "INFO"
                and "DocumentRoot" in finding["detail"]
                and "Movable Type root" in finding["detail"]
                for finding in findings
            )
        )

    def test_cve_check_uses_nvd_client_and_reports_cpe_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_movable_type_fixture(Path(tmp))
            env_file = root / ".env"
            env_file.write_text("NVD_API_KEY=test-nvd-key\n", encoding="utf-8")
            calls: list[dict[str, str]] = []
            api_keys: list[str] = []
            original_fetch = cli.fetch_nvd_cves
            original_api_key = os.environ.pop("NVD_API_KEY", None)
            original_env_file = os.environ.get("IC_MT_HARDENING_ENV_FILE")
            os.environ["IC_MT_HARDENING_ENV_FILE"] = str(env_file)

            def fake_fetch(
                params: dict[str, str],
                nvd_api_key: str,
                timeout: float,
                cache: dict[str, object],
                cache_path: Path | None,
            ) -> tuple[dict[str, object], str, bool]:
                calls.append(params)
                api_keys.append(nvd_api_key)
                return make_nvd_response(), "", False

            cli.fetch_nvd_cves = fake_fetch
            try:
                output = run_cli_capture(
                    [
                        str(root),
                        "--format",
                        "json",
                        "--cve-check",
                        "--nvd-delay",
                        "0",
                        "--perl-bin",
                        "missing-perl-for-test",
                        "--fail-on",
                        "never",
                    ]
                )
            finally:
                cli.fetch_nvd_cves = original_fetch
                if original_api_key is None:
                    os.environ.pop("NVD_API_KEY", None)
                else:
                    os.environ["NVD_API_KEY"] = original_api_key
                if original_env_file is None:
                    os.environ.pop("IC_MT_HARDENING_ENV_FILE", None)
                else:
                    os.environ["IC_MT_HARDENING_ENV_FILE"] = original_env_file

        report = json.loads(output)
        findings = report["findings"]
        self.assertTrue(any("cpeName" in call for call in calls))
        self.assertIn("test-nvd-key", api_keys)
        self.assertTrue(
            any(
                finding["check"] == "cve"
                and finding["source"] == "nvd:cpe"
                and "CVE-2024-0001" in finding["message"]
                for finding in findings
            )
        )


def run_cli_capture(argv: list[str]) -> str:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = cli.main(argv)
    if exit_code not in {0, 1}:
        raise AssertionError(f"unexpected exit code: {exit_code}")
    return stdout.getvalue()


def make_movable_type_fixture(base: Path, insecure_config: bool = False) -> Path:
    root = base / "mt"
    (root / "lib").mkdir(parents=True)
    (root / "plugins" / "ExamplePlugin").mkdir(parents=True)
    (root / "themes" / "classic").mkdir(parents=True)
    (root / "mt-static").mkdir()
    (root / "mt.cgi").write_text("#!/usr/bin/env perl\nuse strict;\n", encoding="utf-8")
    os.chmod(root / "mt.cgi", 0o755)
    (root / "lib" / "MT.pm").write_text(
        "package MT;\nour $VERSION = '8.0.0';\n1;\n",
        encoding="utf-8",
    )
    (root / "plugins" / "ExamplePlugin" / "config.yaml").write_text(
        "id: example-plugin\nname: Example Plugin\nversion: 1.0.0\n",
        encoding="utf-8",
    )
    (root / "themes" / "classic" / "theme.yaml").write_text(
        "id: classic\nname: Classic Theme\nversion: 2.0.0\n",
        encoding="utf-8",
    )
    if insecure_config:
        config = (
            "CGIPath http://example.test/mt/\n"
            "StaticWebPath /mt-static/\n"
            "AdminScript mt.cgi\n"
            "DebugMode 1\n"
            "ObjectDriver DBI::mysql\n"
            "Database mt\n"
            "DBUser mtuser\n"
            "DBPassword secret\n"
        )
    else:
        config = (
            "CGIPath https://example.test/mt/\n"
            "StaticWebPath /mt-static/\n"
            "AdminScript admin.cgi\n"
            "DebugMode 0\n"
            "ObjectDriver DBI::mysql\n"
            "Database mt\n"
            "DBUser mtuser\n"
            "DBPassword secret\n"
            "TempDir /tmp\n"
        )
    (root / "mt-config.cgi").write_text(config, encoding="utf-8")
    os.chmod(root / "mt-config.cgi", 0o640)
    return root


def make_nvd_response() -> dict[str, object]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Movable Type has a test vulnerability.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseSeverity": "HIGH",
                                    "baseScore": 8.1,
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.test/CVE-2024-0001"}],
                }
            }
        ]
    }


if __name__ == "__main__":
    unittest.main()
