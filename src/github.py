import requests


def classify_identity(user, scopes):
    """
    Classify whether the token belongs to a human or non-human identity,
    and assess the security risk.
    """

    # Case 1: Not a human GitHub account
    if user.get("type") != "User":
        return {
            "identity_type": "non-human",
            "risk_level": "high",
            "justification": [
                "Token not associated with a human GitHub account"
            ]
        }

    # Scopes typically associated with automation / CI / high privilege
    high_risk_scopes = {
        "repo",
        "workflow",
        "packages",
        "admin",
        "write"
    }

    if any(scope in high_risk_scopes for scope in scopes):
        return {
            "identity_type": "non-human",
            "risk_level": "high",
            "justification": [
                "Token owned by a human but granted automation-level scopes"
            ]
        }

    # Default: low-risk human token
    return {
        "identity_type": "human",
        "risk_level": "low",
        "justification": [
            "Token owned by GitHub User",
            "Scopes limited to read-only user access"
        ]
    }


def analyze_github_token(token):
    """
    Analyze a GitHub API token:
    - Check if it is valid
    - Identify the associated user
    - Retrieve granted scopes
    - Classify identity and assess risk
    """

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    try:
        response = requests.get(
            "https://api.github.com/user",
            headers=headers,
            timeout=10
        )
    except requests.RequestException as e:
        return {
            "token_valid": False,
            "error": str(e)
        }

    # Invalid token
    if response.status_code != 200:
        return {
            "token_valid": False,
            "http_status": response.status_code
        }

    user_data = response.json()

    # Extract scopes from response headers
    scope_header = response.headers.get("X-OAuth-Scopes", "")
    scopes = [s.strip() for s in scope_header.split(",") if s.strip()]

    result = {
        "token_valid": True,
        "user": {
            "login": user_data.get("login"),
            "id": user_data.get("id"),
            "type": user_data.get("type"),
            "email": user_data.get("email"),
            "company": user_data.get("company"),
        },
        "scopes": scopes
    }

    # Add identity classification and risk assessment
    classification = classify_identity(result["user"], scopes)
    result.update(classification)

    return result
