import csv
import stat
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[2]
ENPASS_EXPORT = PROJECT_ROOT / "testdata" / "enpass" / "export.json"
BITWARDEN_EXPORT = PROJECT_ROOT / "testdata" / "bitwarden" / "Passwords.csv"


def read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.reader(source))


def test_enpass_json_to_bitwarden_csv_via_cli(tmp_path: Path) -> None:
    output = tmp_path / "Passwords.csv"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "enpass_escape.cli",
            str(ENPASS_EXPORT),
            str(output),
            "--target",
            "bitwarden",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert read_csv(output) == read_csv(BITWARDEN_EXPORT)
    assert "Read: 3 | Export: 3" in result.stdout
    assert "Bitwarden items: Logins: 3 | Secure notes: 0" in result.stdout
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
