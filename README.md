# nhi-artifact-analyzer

Security research tool for analyzing leaked **Non-Human Identity (NHI)** artifacts, with an initial focus on GitHub API tokens.

---

## Problem Statement

Non-Human Identities (NHIs), such as API tokens, service accounts, and automation credentials, represent a significant and often underestimated attack surface in modern systems.

Unlike human identities, NHIs:

- Do not rely on multi-factor authentication
- Are frequently long-lived
- Are commonly embedded in source code, logs, configuration files, or CI/CD pipelines
- Can be abused without generating obvious user-facing signals

When exposed, these credentials allow direct authentication to APIs, effectively bypassing traditional user-based security controls and detection mechanisms.

This project focuses on the detection, validation, and risk assessment of leaked GitHub API tokens as a concrete and realistic example of Non-Human Identity exposure.

---

## Tool Overview

The tool performs the following tasks:

- Scans a file for known GitHub token patterns
- Validates detected tokens using the GitHub API
- Determines whether each token is valid, revoked, or invalid
- Extracts the OAuth scopes associated with valid tokens
- Classifies the identity context associated with the token
- Assigns a risk level based on exposure and permissions
- Produces structured, machine-readable JSON output
- Provides remediation-oriented recommendations

---

## How It Works (High-Level)

1. A file is provided as input to the tool  
2. Token-like artifacts are identified using pattern matching  
3. Each detected token is analyzed via the GitHub API  
4. Metadata such as validity, scopes, and identity context is extracted  
5. A risk assessment is performed  
6. Results are returned as structured JSON for further analysis or automation  

---

## Usage

### Set a GitHub API token

A GitHub API token is required to validate detected tokens.  
Read-only access is sufficient.

```bash
export GITHUB_TOKEN=ghp_your_test_token_here
