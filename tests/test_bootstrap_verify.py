from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from tools.bootstrap_verify import main, verify_artifact


class BootstrapVerifyTests(unittest.TestCase):
    def test_exact_external_digest_passes_and_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "package.whl"
            artifact.write_bytes(b"wheel bytes")
            digest = hashlib.sha256(b"wheel bytes").hexdigest()
            self.assertTrue(verify_artifact(artifact, digest)["valid"])
            self.assertEqual(1, main(["--artifact", str(artifact), "--expected-sha256", "0" * 64]))

    def test_hardlinked_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "package.whl"
            artifact.write_bytes(b"wheel bytes")
            os.link(artifact, Path(td) / "alias.whl")
            with self.assertRaisesRegex(ValueError, "artifact_hardlink_rejected"):
                verify_artifact(artifact, hashlib.sha256(b"wheel bytes").hexdigest())


if __name__ == "__main__":
    unittest.main()
