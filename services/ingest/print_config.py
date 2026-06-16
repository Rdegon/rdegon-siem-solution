"""
Print the effective ingest settings for diagnostics.
"""

from __future__ import annotations

from pprint import pprint

from .config import IngestSettings


def main() -> None:
    settings = IngestSettings.load()
    pprint(settings)


if __name__ == "__main__":
    main()
