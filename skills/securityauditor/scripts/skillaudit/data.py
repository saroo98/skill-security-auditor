"""Reference data used by the analyzers and the policy. Extend freely; never shrink."""

from __future__ import annotations

import fnmatch
import ipaddress
import re

SECRET_PATH_PATTERNS: tuple[str, ...] = (
    "*.ssh/id_*", "*.ssh/config", "*.ssh/authorized_keys", "*.aws/credentials", "*.aws/config",
    "*.config/gcloud*", "*.azure/*", "*.env", "*.env.*", "*.netrc", "*.npmrc", "*.pypirc", "*.git-credentials",
    "*.kube/config", "*.docker/config.json", "*Login Data", "*/Cookies", "*.claude/.credentials.json",
    "*.codex/auth.json", "*.gnupg/*", "*keychain*", "*/wallet.dat",
)
SECRET_PATH_EXCEPTIONS: tuple[str, ...] = ("*.env.example", "*.env.sample", "*.env.template")
SECRET_NAME_PARTS: tuple[str, ...] = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")

VENDOR_HOSTS: dict[str, tuple[str, ...]] = {
    "OPENAI": ("openai.com",),
    "ANTHROPIC": ("anthropic.com",),
    "CLAUDE": ("anthropic.com",),
    "GITHUB": ("github.com", "githubusercontent.com"),
    "GH": ("github.com", "githubusercontent.com"),
    "AWS": ("amazonaws.com",),
    "GOOGLE": ("googleapis.com", "google.com"),
    "GEMINI": ("googleapis.com",),
    "AZURE": ("azure.com", "microsoft.com", "windows.net"),
    "HF": ("huggingface.co",),
    "HUGGINGFACE": ("huggingface.co",),
    "SLACK": ("slack.com",),
    "STRIPE": ("stripe.com",),
    "NOTION": ("notion.com", "notion.so"),
    "LINEAR": ("linear.app",),
    "JIRA": ("atlassian.net", "atlassian.com"),
    "GITLAB": ("gitlab.com",),
    "TWILIO": ("twilio.com",),
    "SENDGRID": ("sendgrid.com",),
    "MISTRAL": ("mistral.ai",),
    "GROQ": ("groq.com",),
    "OPENROUTER": ("openrouter.ai",),
}
DROP_HOSTS: tuple[str, ...] = (
    "webhook.site", "pastebin.com", "requestbin.com", "pipedream.net", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "discord.com/api/webhooks", "api.telegram.org", "transfer.sh", "0x0.st", "hookbin.com",
    "interact.sh", "oast.fun", "burpcollaborator.net",
)

_LOOSE_SEP = re.compile(r"[^A-Z0-9]+")


def is_secret_path(path: str) -> bool:
    p = path.replace("\\", "/")
    if any(fnmatch.fnmatch(p, pat) for pat in SECRET_PATH_EXCEPTIONS):
        return False
    return any(fnmatch.fnmatch(p, pat) for pat in SECRET_PATH_PATTERNS)


def is_secret_name(name: str) -> bool:
    upper = name.upper()
    return any(part in _LOOSE_SEP.split(upper) or upper.endswith(part) for part in SECRET_NAME_PARTS)


def vendor_hosts(secret_name: str) -> tuple[str, ...]:
    words = [w for w in _LOOSE_SEP.split(secret_name.upper()) if w]
    for word in words:
        if word in VENDOR_HOSTS:
            return VENDOR_HOSTS[word]
    return ()


def host_matches(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def is_raw_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_drop_host(host: str, url: str | None = None) -> bool:
    target = (url or host).lower()
    for d in DROP_HOSTS:
        if "/" in d:
            if d in target:
                return True
        elif host_matches(host, (d,)):
            return True
    return False
