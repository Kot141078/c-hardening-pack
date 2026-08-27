from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


class RuntimeIntegrityExtensionTest(unittest.TestCase):
    def test_fixture_manifest(self) -> None:
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            [sys.executable, str(root / "tools" / "validate_runtime_integrity_extension.py"), "--verbose"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}",
        )
        self.assertIn("fail=0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
