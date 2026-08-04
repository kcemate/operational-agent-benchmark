from __future__ import annotations

import json
import sys
import tempfile
import unittest
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.verifier import verify_raw_mime_message


class RawMimeVerifierTests(unittest.TestCase):
    def make_workspace(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str]]:
        temp = tempfile.TemporaryDirectory()
        workspace = Path(temp.name)
        (workspace / "input").mkdir()
        (workspace / "submission").mkdir()
        source = {
            "from": "sender@example.test",
            "to": "reviewer@example.test",
            "subject": "Operational update",
            "date": "Mon, 03 Aug 2026 12:00:00 +0000",
            "summary": "Queue processing is stable.",
            "metric": "Completion rate: 98.5%.",
            "next_step": "Review the remaining two records.",
        }
        (workspace / "input/message.json").write_text(json.dumps(source), encoding="utf-8")
        return temp, workspace, source

    def write_good_message(self, workspace: Path, source: dict[str, str]) -> None:
        message = EmailMessage(policy=SMTP)
        message["From"] = source["from"]
        message["To"] = source["to"]
        message["Subject"] = source["subject"]
        message["Date"] = source["date"]
        plain = "\n".join([source["summary"], source["metric"], source["next_step"]]) + "\n"
        html = (
            "<html><body>"
            f"<p>{source['summary']}</p>"
            f"<p>{source['metric']}</p>"
            f"<p>{source['next_step']}</p>"
            "</body></html>\n"
        )
        message.set_content(plain)
        message.add_alternative(html, subtype="html")
        (workspace / "submission/message.eml").write_bytes(message.as_bytes())

    def test_exact_defect_free_message_passes(self) -> None:
        temp, workspace, source = self.make_workspace()
        with temp:
            self.write_good_message(workspace, source)
            results = verify_raw_mime_message(workspace)
        self.assertTrue(all(result.passed for result in results), results)

    def test_invalid_addresses_and_missing_closing_boundary_fail(self) -> None:
        temp, workspace, source = self.make_workspace()
        with temp:
            raw = (
                "From: not-an-address\r\n"
                "To: also-not-an-address\r\n"
                f"Subject: {source['subject']}\r\n"
                f"Date: {source['date']}\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: multipart/alternative; boundary=broken\r\n\r\n"
                "--broken\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                f"{source['summary']}\n{source['metric']}\n{source['next_step']}\n"
            )
            (workspace / "submission/message.eml").write_text(raw, encoding="utf-8")
            results = verify_raw_mime_message(workspace)
        structure = next(r for r in results if r.dimension == "mime_structure")
        self.assertFalse(structure.passed)
        self.assertEqual("invalid_mime", structure.code)

    def test_invented_or_missing_body_content_fails(self) -> None:
        temp, workspace, source = self.make_workspace()
        with temp:
            self.write_good_message(workspace, source)
            path = workspace / "submission/message.eml"
            path.write_bytes(path.read_bytes().replace(source["metric"].encode(), b"Invented metric: 100%."))
            results = verify_raw_mime_message(workspace)
        content = next(r for r in results if r.dimension == "message_content")
        self.assertFalse(content.passed)
        self.assertEqual("content_mismatch", content.code)

    def test_duplicate_singleton_header_or_attachment_fails(self) -> None:
        temp, workspace, source = self.make_workspace()
        with temp:
            self.write_good_message(workspace, source)
            path = workspace / "submission/message.eml"
            raw = path.read_bytes().replace(b"Subject: Operational update\r\n", b"Subject: Operational update\r\nSubject: duplicate\r\n")
            path.write_bytes(raw)
            results = verify_raw_mime_message(workspace)
        structure = next(r for r in results if r.dimension == "mime_structure")
        self.assertFalse(structure.passed)


if __name__ == "__main__":
    unittest.main()
