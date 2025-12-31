import re

GITHUB_TOKEN_REGEX = re.compile(r"ghp_[A-Za-z0-9]{36}")

def find_github_tokens_in_text(text):
    """
    Find GitHub Personal Access Tokens in arbitrary text.
    """
    return list(set(GITHUB_TOKEN_REGEX.findall(text)))
