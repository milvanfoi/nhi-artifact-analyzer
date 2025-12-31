import os
import sys
import json

from github import analyze_github_token
from detector import find_github_tokens_in_text


def scan_file_for_tokens(file_path):
    """
    Read a file and extract GitHub tokens from its content.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found -> {file_path}")
        sys.exit(1)

    return find_github_tokens_in_text(content)


def main():
    """
    Entry point of the tool.

    Usage:
        python src/main.py <file_to_scan>

    The GitHub token used for API analysis must be provided
    via the GITHUB_TOKEN environment variable.
    """

    if len(sys.argv) != 2:
        print("Usage: python src/main.py <file_to_scan>")
        sys.exit(1)

    api_token = os.getenv("GITHUB_TOKEN")
    if not api_token:
        print("Error: GITHUB_TOKEN environment variable is not set.")
        sys.exit(1)

    file_path = sys.argv[1]

    detected_tokens = scan_file_for_tokens(file_path)

    # Base report structure
    report = {
        "scanned_file": file_path,
        "artifacts_found": len(detected_tokens),
        "results": []
    }

    if not detected_tokens:
        report["message"] = "No GitHub tokens detected"
        print(json.dumps(report, indent=2))
        sys.exit(0)

    for token in detected_tokens:
        analysis = analyze_github_token(token)

        # Add interpretation for invalid tokens
        if analysis.get("token_valid") is False:
            analysis["assessment"] = "invalid_or_revoked"
            analysis["recommended_action"] = "rotate_and_investigate_origin"

        report["results"].append(analysis)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
