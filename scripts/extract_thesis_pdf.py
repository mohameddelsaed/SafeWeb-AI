"""Extract selected pages from a PDF to standard output."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from pypdf import PdfReader


def to_markdown(reader: PdfReader) -> str:
    """Convert the source thesis into a clean, editable Markdown baseline."""
    output: list[str] = []
    for page in reader.pages:
        text = page.extract_text() or ""
        lines = text.replace("\r\n", "\n").splitlines()
        if lines and re.fullmatch(r"\s*\d+\s*", lines[0]):
            lines = lines[1:]

        for raw_line in lines:
            line = raw_line.strip()
            for broken, fixed in {
                "â€¢": "-",
                "â€“": "–",
                "â€”": "—",
                "â†’": "→",
                "âž”": "➔",
                "â‰¤": "≤",
                "â‰¥": "≥",
                "â€˜": "‘",
                "â€™": "’",
                "â€œ": "“",
                "â€\u009d": "”",
                "�": "-",
            }.items():
                line = line.replace(broken, fixed)
            if not line:
                output.append("")
                continue
            if re.fullmatch(r"Chapter \d+:\s+.+", line):
                output.append(f"# {line}")
            elif re.fullmatch(r"\d+\.\d+(?:\.\d+){0,2}\s+.+", line):
                depth = min(line.split(maxsplit=1)[0].count(".") + 1, 4)
                output.append(f"{'#' * depth} {line}")
            elif re.fullmatch(r"Appendix [A-Z](?::|\s).+", line):
                output.append(f"# {line}")
            elif line in {
                "Abstract",
                "Acknowledgements",
                "Table of Contents",
                "List of Figures",
                "List of Tables",
                "List of Abbreviations",
                "References",
            }:
                output.append(f"# {line}")
            elif re.fullmatch(r"End of Chapter \d+", line):
                continue
            else:
                output.append(line)

    markdown = "\n".join(output)
    markdown = re.sub(r"\n{3,}", "\n\n", markdown)
    return markdown.strip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int)
    parser.add_argument("--markdown-output")
    args = parser.parse_args()

    reader = PdfReader(args.pdf)
    if args.markdown_output:
        output = Path(args.markdown_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(to_markdown(reader), encoding="utf-8")
        print(f"WROTE {output} ({len(reader.pages)} pages)")
        return

    end = args.end or len(reader.pages)
    print(f"PAGES {len(reader.pages)}")
    for page_number in range(args.start, min(end, len(reader.pages)) + 1):
        text = reader.pages[page_number - 1].extract_text() or ""
        print(f"\n--- PAGE {page_number} ---\n{text}")


if __name__ == "__main__":
    main()
