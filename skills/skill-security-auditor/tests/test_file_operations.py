from pathlib import Path

from check_file_operations import scan_text


def rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in scan_text(Path("script.sh"), "script.sh", text)}


def test_detects_recursive_delete_and_root_delete():
    rules = rule_ids("rm -rf /")
    assert "file-rm-rf" in rules
    assert "file-recursive-delete-root-or-home" in rules


def test_detects_dotenv_read():
    assert "credential-dotenv-read" in rule_ids("cat .env")


def test_detects_ssh_key_read():
    assert "credential-ssh-key-read" in rule_ids("cat ~/.ssh/id_rsa")


def test_detects_cloud_config_read():
    assert "credential-cloud-config-read" in rule_ids("cat ~/.aws/credentials")


def test_detects_github_token_reference():
    assert "credential-github-token-read" in rule_ids("echo $GITHUB_TOKEN")


def test_detects_environment_dump():
    assert "env-mass-dump" in rule_ids("printenv")


def test_detects_hidden_dotfile_write():
    assert "hidden-dotfile-write" in rule_ids("echo data > ~/.hidden-agent-state")
