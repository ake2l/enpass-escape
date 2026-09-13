from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

import typer

from enpass_escape.deduplication import deduplicate
from enpass_escape.exporters import (
    APPLE_CSV_HEADER,
    BITWARDEN_CSV_HEADER,
    BITWARDEN_IMPORT_LIMIT,
    GOOGLE_CSV_HEADER,
    GOOGLE_IMPORT_LIMIT,
    _bitwarden_type,
    generate_otpauth_url,
    google_website_entries,
    write_apple_csv,
    write_apple_csv_from_dicts,
    write_bitwarden_csv,
    write_google_csv,
)
from enpass_escape.models import DeduplicationResult, DuplicatePolicy, Entry, Target
from enpass_escape.parser import (
    ENPASS_FIELD_MAPPINGS,
    FIELD_TYPE_MAPPINGS,
    parse_enpass,
    parse_enpass_csv,
    parse_enpass_json,
)


__all__ = [
    "APPLE_CSV_HEADER",
    "BITWARDEN_CSV_HEADER",
    "BITWARDEN_IMPORT_LIMIT",
    "DeduplicationResult",
    "DuplicatePolicy",
    "ENPASS_FIELD_MAPPINGS",
    "Entry",
    "FIELD_TYPE_MAPPINGS",
    "GOOGLE_CSV_HEADER",
    "GOOGLE_IMPORT_LIMIT",
    "Target",
    "app",
    "deduplicate",
    "generate_otpauth_url",
    "google_website_entries",
    "main",
    "parse_enpass",
    "parse_enpass_csv",
    "parse_enpass_json",
    "transform_enpass_csv_to_apple",
    "transform_enpass_to_apple",
    "write_apple_csv",
    "write_apple_csv_from_dicts",
    "write_bitwarden_csv",
    "write_google_csv",
]


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
    output_file: str | None = typer.Argument(
        None, help="Output CSV path. A target-specific name is used by default."
    ),
    target: Target = typer.Option(Target.APPLE, help="Password manager to export for."),
    duplicates: DuplicatePolicy = typer.Option(
        DuplicatePolicy.NEWEST, help="How duplicate credentials are handled."
    ),
    include_archived: bool = typer.Option(
        False, help="Include archived Enpass entries."
    ),
    include_trashed: bool = typer.Option(False, help="Include trashed Enpass entries."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Analyze without writing files."
    ),
    force: bool = typer.Option(
        False, "--force", help="Replace an existing output file."
    ),
) -> None:
    """Convert an Enpass export to Apple, Bitwarden, or Google CSV."""
    try:
        entries = parse_enpass(
            enpass_input_file,
            include_archived=include_archived,
            include_trashed=include_trashed,
        )
        deduplicated = deduplicate(entries, duplicates)
        export_entries = list(deduplicated.entries)
        skip_reasons: Counter[str] = Counter()
        skipped_totp = 0
        skipped_attachments = sum(entry.attachment_count for entry in entries)
        if target == Target.GOOGLE:
            skipped_totp = sum(bool(entry.totp) for entry in export_entries)
            export_entries, skip_reasons = google_website_entries(export_entries)

        typer.echo(
            f"Read: {len(entries)} | Export: {len(export_entries)} | "
            f"Duplicates removed: {deduplicated.removed} | "
            f"Conflicts kept: {deduplicated.conflicts}"
        )
        skipped = sum(skip_reasons.values())
        details = ", ".join(
            f"{reason}: {count}" for reason, count in skip_reasons.items()
        )
        typer.echo(f"Skipped: {skipped}" + (f" ({details})" if details else ""))
        typer.echo(
            f"Not migrated: TOTP: {skipped_totp} | Attachments: {skipped_attachments}"
        )
        if target == Target.BITWARDEN:
            secure_notes = sum(
                _bitwarden_type(entry) == "note" for entry in export_entries
            )
            typer.echo(
                f"Bitwarden items: Logins: {len(export_entries) - secure_notes} | "
                f"Secure notes: {secure_notes}"
            )
        if dry_run:
            typer.echo("Dry run: no files created.")
            return

        destination = output_file or f"export-{target.value}-passwords.csv"
        if target == Target.GOOGLE:
            paths = write_google_csv(export_entries, destination, force=force)
        elif target == Target.BITWARDEN:
            paths = write_bitwarden_csv(export_entries, destination, force=force)
        else:
            write_apple_csv(export_entries, destination, force=force)
            paths = (Path(destination),)
        typer.echo(f"Created: {', '.join(str(path) for path in paths)}")
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as error:
        typer.secho(f"Conversion failed: {error}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from error


app = typer.Typer(add_completion=False)
app.command()(main)


if __name__ == "__main__":
    app()
