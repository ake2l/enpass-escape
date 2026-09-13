from __future__ import annotations

import csv
import itertools
import json
import os
import re
import tempfile
import urllib.parse
import warnings
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import typer


ENPASS_FIELD_MAPPINGS: dict[str, tuple[str, ...]] = {
    "Title": ("Title", "Name", "Login name", "ItemName"),
    "URL": ("URL", "Website", "Web Address", "Login URL"),
    "Username": ("Username", "User ID", "Login ID", "Login Username"),
    "Password": ("Password", "*Password", "Passphrase", "Login Password"),
    "TOTP": (
        "TOTP",
        "TOTP Secret",
        "One-Time Password",
        "One-time code",
        "OTP Secret",
        "OTP",
        "TOTP Key",
    ),
    "Notes": ("Note", "Notes", "Description", "Details", "Memo", "My notes"),
}
FIELD_TYPE_MAPPINGS = {
    "url": "URL",
    "username": "Username",
    "password": "Password",
    "totp": "TOTP",
}
APPLE_CSV_HEADER = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]


@dataclass(frozen=True, slots=True)
class Entry:
    title: str = ""
    url: str = ""
    username: str = ""
    password: str = ""
    notes: str = ""
    totp: str = ""
    extra_notes: tuple[str, ...] = ()
    updated_at: int | None = None
    uuid: str = ""


def _mapped_field(label: str, field_type: str = "") -> str | None:
    if mapped := FIELD_TYPE_MAPPINGS.get(field_type.casefold()):
        return mapped
    folded_label = label.casefold()
    return next(
        (
            name
            for name, options in ENPASS_FIELD_MAPPINGS.items()
            if folded_label in (option.casefold() for option in options)
        ),
        None,
    )


def generate_otpauth_url(secret_key: str, title: str = "", username: str = "") -> str:
    """Return an otpauth URI for an Enpass TOTP secret."""
    if not secret_key:
        return ""
    if secret_key.casefold().startswith("otpauth://"):
        return secret_key

    cleaned_secret = secret_key.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z2-7=]+", cleaned_secret):
        warnings.warn(
            f"TOTP secret for '{title or username}' contains invalid Base32 characters",
            stacklevel=2,
        )

    issuer = title.strip()
    account = username.strip()
    label = f"{issuer}:{account}" if issuer and account else account or issuer or "UnknownAccount"
    params = {"secret": cleaned_secret, "algorithm": "SHA1", "digits": "6", "period": "30"}
    if issuer:
        params["issuer"] = issuer
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def _entry_from_fields(
    *,
    title: str,
    notes: str,
    fields: Iterable[Mapping[str, object]],
    updated_at: int | None = None,
    uuid: str = "",
) -> Entry:
    values: dict[str, str] = {}
    extra_notes: list[str] = []

    for field in fields:
        if field.get("deleted"):
            continue
        label = str(field.get("label", "")).strip()
        raw_value = field.get("value", "")
        if not isinstance(raw_value, str):
            continue
        mapped = _mapped_field(label, str(field.get("type", "")))
        value = raw_value if mapped == "Password" else raw_value.strip()
        if not label or not value:
            continue
        if mapped and mapped not in values:
            values[mapped] = value
        elif field.get("type") != "section":
            extra_notes.append(f"{label}: {value}")

    return Entry(
        title=title,
        url=values.get("URL", ""),
        username=values.get("Username", ""),
        password=values.get("Password", ""),
        notes=notes,
        totp=values.get("TOTP", ""),
        extra_notes=tuple(extra_notes),
        updated_at=updated_at,
        uuid=uuid,
    )


def parse_enpass_json(
    input_filepath: str | Path,
    *,
    include_archived: bool = False,
    include_trashed: bool = False,
) -> list[Entry]:
    """Parse an Enpass JSON export into normalized entries."""
    with Path(input_filepath).open(encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
        raise ValueError("Invalid Enpass JSON export")

    entries: list[Entry] = []
    for item in data.get("items", []):
        if not isinstance(item, dict):
            raise ValueError("Invalid item in Enpass JSON export")
        if (item.get("archived") and not include_archived) or (
            item.get("trashed") and not include_trashed
        ):
            continue
        fields = item.get("fields", [])
        if not isinstance(fields, list) or not all(isinstance(field, dict) for field in fields):
            raise ValueError("Invalid fields in Enpass JSON export")
        timestamp = item.get("updated_at")
        entries.append(
            _entry_from_fields(
                title=str(item.get("title", "")),
                notes=str(item.get("note", "")),
                fields=fields,
                updated_at=timestamp if isinstance(timestamp, int) and not isinstance(timestamp, bool) else None,
                uuid=str(item.get("uuid", "")),
            )
        )
    return entries


def _entry_from_key_value_row(row: Sequence[str]) -> Entry:
    fields = (
        {"label": row[index].strip(), "value": row[index + 1] if index + 1 < len(row) else ""}
        for index in range(1, len(row), 2)
    )
    return _entry_from_fields(title=row[0].strip() if row else "", notes="", fields=fields)


def parse_enpass_csv(input_filepath: str | Path) -> list[Entry]:
    """Parse header-based or Enpass key/value CSV exports."""
    with Path(input_filepath).open(newline="", encoding="utf-8-sig") as source:
        reader = csv.reader(source)
        try:
            first_row = next(reader)
        except StopIteration:
            raise csv.Error("CSV file has no rows") from None
        if not first_row:
            raise csv.Error("CSV file has an empty first row")

        title_labels = {label.casefold() for label in ENPASS_FIELD_MAPPINGS["Title"]}
        if first_row[0].strip().casefold() not in title_labels:
            return [
                _entry_from_key_value_row(row)
                for row in itertools.chain([first_row], reader)
                if any(cell.strip() for cell in row)
            ]

        header = [name.strip() for name in first_row]
        indices = {name.casefold(): index for index, name in enumerate(header)}
        mapped_indices: dict[str, int] = {}
        for name, options in ENPASS_FIELD_MAPPINGS.items():
            for option in options:
                if option.casefold() in indices:
                    mapped_indices[name] = indices[option.casefold()]
                    break

        entries: list[Entry] = []
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            row = [*row, *([""] * max(0, len(header) - len(row)))]

            def value(name: str, *, strip: bool = True) -> str:
                index = mapped_indices.get(name)
                if index is None or index >= len(row):
                    return ""
                return row[index].strip() if strip else row[index]

            used = set(mapped_indices.values())
            extras = tuple(
                f"{header[index]}: {cell.strip()}"
                for index, cell in enumerate(row[: len(header)])
                if index not in used and cell.strip()
            )
            entries.append(
                Entry(
                    title=value("Title"),
                    url=value("URL"),
                    username=value("Username"),
                    password=value("Password", strip=False),
                    notes=value("Notes"),
                    totp=value("TOTP"),
                    extra_notes=extras,
                )
            )
        return entries


def parse_enpass(
    input_filepath: str | Path,
    *,
    include_archived: bool = False,
    include_trashed: bool = False,
) -> list[Entry]:
    suffix = Path(input_filepath).suffix.casefold()
    if suffix == ".json":
        return parse_enpass_json(
            input_filepath,
            include_archived=include_archived,
            include_trashed=include_trashed,
        )
    if suffix == ".csv":
        return parse_enpass_csv(input_filepath)
    raise ValueError("Input must be an Enpass .json or .csv export")


def _write_csv(
    output_filepath: str | Path,
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    force: bool = False,
) -> None:
    output = Path(output_filepath)
    if output.exists() and not force:
        raise FileExistsError(f"Output already exists: {output}")
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(file_descriptor, "w", newline="", encoding="utf-8") as destination:
            writer = csv.writer(destination)
            writer.writerow(header)
            writer.writerows(rows)
        os.replace(temporary_name, output)
        os.chmod(output, 0o600)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _notes(entry: Entry) -> str:
    return "\n".join(part for part in (entry.notes, *entry.extra_notes) if part)


def write_apple_csv(
    entries: Iterable[Entry], output_filepath: str | Path, *, force: bool = False
) -> None:
    _write_csv(
        output_filepath,
        APPLE_CSV_HEADER,
        (
            (
                entry.title,
                entry.url,
                entry.username,
                entry.password,
                _notes(entry),
                generate_otpauth_url(entry.totp, entry.title, entry.username),
            )
            for entry in entries
        ),
        force=force,
    )


def write_apple_csv_from_dicts(
    dicts: Iterable[Mapping[str, object]], output_filepath: str | Path, *, force: bool = False
) -> None:
    """Compatibility wrapper for the original public helper."""
    entries = (
        Entry(
            title=str(item.get("Title", "")),
            url=str(item.get("URL", "")),
            username=str(item.get("Username", "")),
            password=str(item.get("Password", "")),
            notes=str(item.get("Notes", "")),
            totp=str(item.get("TOTP", "")),
            extra_notes=tuple(str(note) for note in item.get("_extra", []) if isinstance(note, str)),
        )
        for item in dicts
    )
    write_apple_csv(entries, output_filepath, force=force)


def transform_enpass_csv_to_apple(
    input_filepath: str | Path, output_filepath: str | Path, *, force: bool = False
) -> None:
    write_apple_csv(parse_enpass_csv(input_filepath), output_filepath, force=force)


def transform_enpass_to_apple(
    input_filepath: str | Path,
    output_filepath: str | Path,
    *,
    include_archived: bool = False,
    include_trashed: bool = False,
    force: bool = False,
) -> None:
    write_apple_csv(
        parse_enpass(
            input_filepath,
            include_archived=include_archived,
            include_trashed=include_trashed,
        ),
        output_filepath,
        force=force,
    )


def main(
    enpass_input_file: str = typer.Argument(
        "export-enpass.csv", help="Path to your Enpass export CSV or JSON file."
    ),
    apple_output_file: str = typer.Argument(
        "export-apple-passwords.csv", help="Desired Apple Passwords CSV path."
    ),
    include_archived: bool = typer.Option(False, help="Include archived Enpass entries."),
    include_trashed: bool = typer.Option(False, help="Include trashed Enpass entries."),
    force: bool = typer.Option(False, "--force", help="Replace an existing output file."),
) -> None:
    """Convert an Enpass CSV or JSON export to Apple Passwords CSV."""
    try:
        transform_enpass_to_apple(
            enpass_input_file,
            apple_output_file,
            include_archived=include_archived,
            include_trashed=include_trashed,
            force=force,
        )
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as error:
        typer.secho(f"Conversion failed: {error}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from error


app = typer.Typer(add_completion=False)
app.command()(main)


if __name__ == "__main__":
    app()
