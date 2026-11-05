import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
FEED_PATH = "/app/feed_task"
PRODUCT = "Demo Board"
ARTICLE = {
    "vendor": "Example",
    "product": PRODUCT,
    "KLA_id": "KLA-TEST",
    "description": "Test advisory",
    "publish_date": "2024-01-01",
    "start_vuln_version": "1.0",
    "fixed_version": "1.1",
}


class PostgreSQLIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="safeboard-test-")
        cls.project = Path(cls.temporary.name)
        cls.project_name = "sbtest" + secrets.token_hex(6)
        cls.compose = [
            "docker", "compose", "-p", cls.project_name,
            "-f", str(cls.project / "compose.yaml"),
        ]
        try:
            for name in ("tool.py", "db.py", "load.py", "requirements.txt", "Dockerfile", "compose.yaml"):
                shutil.copyfile(ROOT / name, cls.project / name)
            (cls.project / "feed_task").mkdir()
            (cls.project / ".env").write_text(
                "POSTGRES_DB=safeboard\n"
                "POSTGRES_USER=sbtester\n"
                f"POSTGRES_PASSWORD={secrets.token_hex(24)}\n",
                encoding="utf-8",
            )
            cls.compose_run("build", "app", timeout=600)
            cls.compose_run("up", "-d", "--wait", "db", timeout=180)
        except BaseException:
            cls.cleanup_project()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.cleanup_project()

    @classmethod
    def cleanup_project(cls):
        if hasattr(cls, "compose"):
            subprocess.run(
                cls.compose + ["down", "--volumes", "--remove-orphans"],
                cwd=cls.project, capture_output=True, text=True, timeout=90,
                check=False,
            )
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    @classmethod
    def compose_run(cls, *args, timeout=120, check=True):
        result = subprocess.run(
            cls.compose + list(args), cwd=cls.project,
            capture_output=True, text=True, timeout=timeout,
        )
        if check and result.returncode:
            raise AssertionError(
                f"isolated Compose command {args!r} failed ({result.returncode}):\n"
                f"{result.stdout}\n{result.stderr}"
            )
        return result

    def setUp(self):
        self.write_feed("versions.json", [
            {"vendor": "Example", "product": PRODUCT, "version": version}
            for version in ("1.0", "1.1")
        ])
        self.write_feed("vulnerabilities.json", [ARTICLE])

    def write_feed(self, name, rows):
        destination = self.project / "feed_task" / name
        replacement = destination.with_name(name + ".new")
        replacement.write_text(json.dumps(rows), encoding="utf-8")
        os.replace(replacement, destination)

    @staticmethod
    def feed_args():
        return [
            "--versions", f"{FEED_PATH}/versions.json",
            "--vulnerabilities", f"{FEED_PATH}/vulnerabilities.json",
        ]

    def test_one_shot_multiword_case_and_exact_version(self):
        vulnerable = self.compose_run(
            "run", "--rm", "-T", "app", "demo", "board",
            "--version", "1.0", *self.feed_args(), timeout=120,
        )
        self.assertIn("KLA-TEST", vulnerable.stdout)

        fixed = self.compose_run(
            "run", "--rm", "-T", "app", "demo", "board",
            "--version", "1.1", *self.feed_args(), timeout=120,
        )
        self.assertIn("Для этой версии уязвимости не найдены", fixed.stdout)
        self.assertNotIn("KLA-TEST", fixed.stdout)

        unknown = self.compose_run(
            "run", "--rm", "-T", "app", "demo", "board",
            "--version", "1.2", *self.feed_args(), timeout=120, check=False,
        )
        self.assertEqual(unknown.returncode, 1, unknown.stdout + unknown.stderr)
        self.assertIn("Версия не найдена в фиде", unknown.stdout)

    def test_repl_refresh_rollback_and_retry(self):
        process = subprocess.Popen(
            self.compose + [
                "run", "--rm", "-T", "-e", "PYTHONUNBUFFERED=1", "app",
                "--repl", *self.feed_args(),
            ],
            cwd=self.project, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0,
        )
        self.addCleanup(self.stop_process, process)
        self.wait_for_prompt(process, timeout=120)

        self.assertIn("KLA-TEST", self.query_repl(process, "vulns demo board 1.0"))

        no_longer_vulnerable = {**ARTICLE, "fixed_version": "1.0"}
        self.write_feed("vulnerabilities.json", [no_longer_vulnerable])
        refreshed = self.query_repl(process, "vulns demo board 1.0")
        self.assertIn("Для этой версии уязвимости не найдены", refreshed)
        self.assertNotIn("KLA-TEST", refreshed)

        self.write_feed("versions.json", [
            {"vendor": "Example", "product": PRODUCT, "version": version}
            for version in ("1.0", "1.1", "1.2")
        ])
        self.assertIn("1.2", self.query_repl(process, "safe demo board"))

        bad_article = {key: value for key, value in ARTICLE.items() if key != "fixed_version"}
        self.write_feed("vulnerabilities.json", [bad_article])
        failed = self.query_repl(process, "vulns demo board 1.0")
        self.assertIn("Не удалось обновить фиды", failed)
        self.assertNotIn("Для этой версии уязвимости не найдены", failed)
        self.assertNotIn("KLA-TEST", failed)

        stored = self.compose_run(
            "run", "--rm", "-T", "--entrypoint", "python", "app", "-c",
            "import os, psycopg; "
            "c=psycopg.connect(host=os.environ['DB_HOST'],dbname=os.environ['POSTGRES_DB'],"
            "user=os.environ['POSTGRES_USER'],password=os.environ['POSTGRES_PASSWORD']); "
            "print(c.execute(\"SELECT (SELECT count(*) FROM article WHERE kla_id='KLA-TEST' "
            "AND fixed_version='1.0'), (SELECT count(*) FROM versions WHERE version='1.2')\").fetchone()); "
            "c.close()",
            timeout=120,
        )
        self.assertIn("(1, 1)", stored.stdout)

        self.write_feed("vulnerabilities.json", [ARTICLE])
        self.assertIn("KLA-TEST", self.query_repl(process, "vulns demo board 1.0"))
        process.stdin.close()
        self.assertEqual(process.wait(timeout=30), 0)

    def test_startup_import_hash_is_used_for_first_repl_command(self):
        # Exercise the handoff deterministically: edit a temporary feed after the
        # real import but before run_repl receives the committed snapshot hashes.
        probe = textwrap.dedent(r'''
            import contextlib
            import io
            import json
            import os
            from pathlib import Path
            import psycopg
            import sys
            import tempfile
            from db import create_schema
            from load import load_feeds
            from tool import run_repl

            with tempfile.TemporaryDirectory() as directory:
                vuln = Path(directory) / "vulnerabilities.json"
                versions = Path(directory) / "versions.json"
                vuln.write_bytes(Path("/app/feed_task/vulnerabilities.json").read_bytes())
                versions.write_bytes(Path("/app/feed_task/versions.json").read_bytes())
                with psycopg.connect(
                    host=os.environ["DB_HOST"], dbname=os.environ["POSTGRES_DB"],
                    user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"],
                    autocommit=True,
                ) as conn:
                    create_schema(conn)
                    imported_hashes = load_feeds(conn, vuln, versions)
                    rows = json.loads(vuln.read_text(encoding="utf-8"))
                    rows[0]["fixed_version"] = "1.0"
                    vuln.write_text(json.dumps(rows), encoding="utf-8")
                    output = io.StringIO()
                    original_stdin = sys.stdin
                    try:
                        sys.stdin = io.StringIO("vulns demo board 1.0\n")
                        with contextlib.redirect_stdout(output):
                            run_repl(conn, vuln, versions, imported_hashes)
                    finally:
                        sys.stdin = original_stdin
                    assert "Для этой версии уязвимости не найдены" in output.getvalue(), output.getvalue()
                    assert "KLA-TEST" not in output.getvalue(), output.getvalue()
                    assert conn.execute("SELECT fixed_version FROM article WHERE kla_id='KLA-TEST'").fetchone()[0] == "1.0"
                    print("STARTUP_HASH_REFRESH_OK")
        ''')
        result = self.compose_run(
            "run", "--rm", "-T", "--entrypoint", "python", "app", "-c", probe,
            timeout=120,
        )
        self.assertIn("STARTUP_HASH_REFRESH_OK", result.stdout)

    def query_repl(self, process, command):
        process.stdin.write((command + "\n").encode())
        process.stdin.flush()
        return self.wait_for_prompt(process)

    def wait_for_prompt(self, process, timeout=30):
        chunks = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"safeboard> " not in chunks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"REPL prompt timed out: {chunks.decode(errors='replace')}")
                if not selector.select(remaining):
                    raise AssertionError(f"REPL prompt timed out: {chunks.decode(errors='replace')}")
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    raise AssertionError(f"REPL exited early ({process.poll()}): {chunks.decode(errors='replace')}")
                chunks.extend(data)
        return chunks.decode(errors="replace")

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
