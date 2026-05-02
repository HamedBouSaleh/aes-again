#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main():
    os.chdir(PROJECT_ROOT)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    stdout = result.stdout
    stderr = result.stderr

    print("=" * 60)
    print("EECE 455 Project 7 — Full test run")
    print("=" * 60)
    print(stdout)
    if stderr:
        print("STDERR:", stderr)

    if result.returncode != 0:
        print("\n" + "!" * 60)
        print("SOME TESTS FAILED")
        print("!" * 60)
        if "FAILED" in stdout:
            for line in stdout.splitlines():
                if "FAILED" in line:
                    print("  ", line.strip())
        sys.exit(1)

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    main()
