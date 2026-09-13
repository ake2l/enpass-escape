import csv
import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from enpass_escape import cli


TESTDATA_DIR = Path(__file__).parents[2] / "testdata"
ENPASS_CSV = TESTDATA_DIR / "enpass" / "export.csv"
ENPASS_JSON = TESTDATA_DIR / "enpass" / "export.json"


def read_csv(filepath: Path) -> list[list[str]]:
    with filepath.open(newline="", encoding="utf-8") as source:
        return list(csv.reader(source))


def write_json(filepath: Path, items: list[dict[str, object]]) -> None:
    filepath.write_text(json.dumps({"items": items}), encoding="utf-8")


def login_item(
    title: str,
    *,
    archived: int = 0,
    trashed: int = 0,
) -> dict[str, object]:
    return {
        "title": title,
        "note": "original note",
        "updated_at": 123,
        "uuid": title,
        "archived": archived,
        "trashed": trashed,
        "fields": [
            {"label": "Site", "type": "url", "value": "https://example.com"},
            {"label": "Login", "type": "username", "value": "user@example.com"},
            {"label": "Secret", "type": "password", "value": " password with spaces "},
            {"label": "Any label", "type": "totp", "value": "JBSWY3DPEHPK3PXP"},
            {"label": "Custom", "type": "text", "value": "kept"},
        ],
    }


def test_json_parser_uses_types_without_copying_credentials_to_notes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "export.json"
    item = login_item("Example")
    item["attachments"] = [{"name": "example.txt", "data": "test"}]
    write_json(source, [item])

    entry = cli.parse_enpass_json(source)[0]

    assert entry.password == " password with spaces "
    assert entry.totp == "JBSWY3DPEHPK3PXP"
    assert entry.updated_at == 123
    assert entry.extra_notes == ("Custom: kept",)
    assert entry.attachment_count == 1


def test_json_parser_excludes_archived_and_trashed_entries(tmp_path: Path) -> None:
    source = tmp_path / "export.json"
    write_json(
        source,
        [
            login_item("Active"),
            login_item("Archived", archived=1),
            login_item("Trash", trashed=1),
        ],
    )

    assert [entry.title for entry in cli.parse_enpass_json(source)] == ["Active"]
    assert (
        len(cli.parse_enpass_json(source, include_archived=True, include_trashed=True))
        == 3
    )


@pytest.mark.parametrize("source", [ENPASS_CSV, ENPASS_JSON])
def test_bundled_exports_convert_to_apple(source: Path, tmp_path: Path) -> None:
    output = tmp_path / "apple.csv"

    cli.transform_enpass_to_apple(source, output)

    rows = read_csv(output)
    assert rows[0] == cli.APPLE_CSV_HEADER
    assert len(rows) == 4
    assert any(row[5].startswith("otpauth://") for row in rows[1:])
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_output_is_not_overwritten_without_force(tmp_path: Path) -> None:
    output = tmp_path / "apple.csv"
    output.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        cli.write_apple_csv([], output)

    assert output.read_text(encoding="utf-8") == "keep me"


def test_unknown_input_format_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"\.json or \.csv"):
        cli.parse_enpass(tmp_path / "export.txt")


def test_newest_duplicate_wins() -> None:
    older = cli.Entry(
        title="Old",
        url="https://EXAMPLE.com:443/login",
        username="User",
        password="old",
        updated_at=1,
    )
    newer = cli.Entry(
        title="New",
        url="https://example.com/login",
        username="user",
        password="new",
        updated_at=2,
    )

    result = cli.deduplicate([older, newer])

    assert result.entries == (newer,)
    assert result.removed == 1
    assert result.conflicts == 0


def test_ambiguous_duplicate_is_kept() -> None:
    first = cli.Entry(
        url="https://example.com", username="user", password="one", updated_at=1
    )
    second = cli.Entry(
        url="https://example.com/", username="USER", password="two", updated_at=1
    )

    result = cli.deduplicate([first, second])

    assert result.entries == (first, second)
    assert result.removed == 0
    assert result.conflicts == 1


def test_exact_duplicates_do_not_need_timestamps() -> None:
    entry = cli.Entry(url="https://example.com", username="user", password="same")

    result = cli.deduplicate([entry, entry], cli.DuplicatePolicy.EXACT)

    assert result.entries == (entry,)
    assert result.removed == 1


def test_google_export_contains_only_website_passwords(tmp_path: Path) -> None:
    website = cli.Entry(
        title="Example",
        url="https://example.com",
        username="user",
        password="secret",
        notes="note",
        totp="JBSWY3DPEHPK3PXP",
        extra_notes=("Card number: not for Google",),
    )
    entries, skipped = cli.google_website_entries(
        [
            website,
            cli.Entry(url="android://app", password="secret"),
            cli.Entry(url="https://empty"),
        ]
    )
    output = tmp_path / "google.csv"

    paths = cli.write_google_csv(entries, output)

    assert paths == (output,)
    assert skipped == 2
    assert read_csv(output) == [
        cli.GOOGLE_CSV_HEADER,
        ["https://example.com", "user", "secret", "Title: Example\nnote"],
    ]


def test_enpass_json_to_google_csv(tmp_path: Path) -> None:
    source = tmp_path / "export.json"
    output = tmp_path / "google.csv"
    write_json(source, [login_item("Example")])

    result = CliRunner().invoke(
        cli.app,
        [str(source), str(output), "--target", "google"],
    )

    assert result.exit_code == 0
    assert "TOTP not migrated 1" in result.output
    assert read_csv(output) == [
        cli.GOOGLE_CSV_HEADER,
        [
            "https://example.com",
            "user@example.com",
            " password with spaces ",
            "Title: Example\noriginal note",
        ],
    ]


def test_google_export_splits_at_import_limit(tmp_path: Path) -> None:
    entries = [
        cli.Entry(url=f"https://example.com/{index}", password="secret")
        for index in range(cli.GOOGLE_IMPORT_LIMIT + 1)
    ]

    paths = cli.write_google_csv(entries, tmp_path / "google.csv")

    assert [path.name for path in paths] == ["google-1.csv", "google-2.csv"]
    assert len(read_csv(paths[0])) == cli.GOOGLE_IMPORT_LIMIT + 1
    assert len(read_csv(paths[1])) == 2


def test_google_dry_run_writes_nothing() -> None:
    result = CliRunner().invoke(
        cli.app,
        [str(ENPASS_JSON), "--target", "google", "--dry-run"],
    )

    assert result.exit_code == 0
    assert "TOTP not migrated 1" in result.output
    assert "attachments not migrated 0" in result.output
    assert "Created:" not in result.output
