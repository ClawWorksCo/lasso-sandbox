"""LASSO authentication — GitHub OAuth Device Flow.

Provides browser-based authentication for CLI tools that cannot use
redirect-based OAuth. The user opens a URL, enters a code, and LASSO
polls until the token is granted.
"""

from lasso.auth.github import GitHubAuth

__all__ = ["GitHubAuth"]
