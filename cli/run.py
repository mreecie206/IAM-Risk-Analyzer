# cli/run.py

import argparse
import sys

from src.analyzer import Analyzer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IAM Risk Analyzer CLI"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to IAM configuration JSON file"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON instead of text"
    )

    args = parser.parse_args()

    analyzer = Analyzer()
    try:
        report = analyzer.analyze_from_file(args.config)
    except Exception as exc:
        print(f"[Error] Failed to analyze {args.config}: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(report.to_json())
    else:
        print(report.to_text())


if __name__ == "__main__":
    main()
