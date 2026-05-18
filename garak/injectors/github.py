# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""GitHub injector — plants payloads as GitHub issues.

Opens an issue in a given repository using the GitHub REST API.
Reads the token from the ``GITHUB_TOKEN`` environment variable
(following garak's ``key_env_var`` convention).

Example config::

    injectors:
      github:
        type: "injectors.github.GitHubInjector"
        config:
          owner: "myorg"
          repo: "myrepo"
          title_prefix: "Bug Report: "

Set the token via environment variable::

    export GITHUB_TOKEN="ghp_..."
"""

import json
import logging
import os
import urllib.request
import urllib.error

from garak.injectors.base import Injector, InjectionResult

logger = logging.getLogger(__name__)

# Environment variable name — same convention as garak generators.
_GITHUB_TOKEN_ENV_VAR = "GITHUB_TOKEN"


class GitHubInjector(Injector):
    """Inject content as a GitHub issue in a repository."""

    _API_URL = "https://api.github.com"

    def __init__(self, config: dict | None = None):
        super().__init__(config)
        self.api_key = os.getenv(_GITHUB_TOKEN_ENV_VAR, default="")
        if not self.api_key:
            logger.warning(
                "GitHubInjector: %s environment variable is not set",
                _GITHUB_TOKEN_ENV_VAR,
            )

    def inject(self, payload: str, **kwargs) -> InjectionResult:
        token = self.api_key
        owner = self.config.get("owner", "")
        repo = self.config.get("repo", "")
        title = kwargs.get("title") or self.config.get("title", "Automated report")

        if not token or not owner or not repo:
            return InjectionResult(
                success=False,
                error="token, owner, and repo must be configured",
            )

        url = f"{self._API_URL}/repos/{owner}/{repo}/issues"
        data = json.dumps({"title": title, "body": payload}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            logger.error(
                "GitHubInjector POST %s returned %d: %s", url, e.code, error_body
            )
            return InjectionResult(success=False, error=f"HTTP {e.code}: {error_body}")
        except Exception as e:
            logger.error("GitHubInjector POST %s failed: %s", url, e)
            return InjectionResult(success=False, error=str(e))

        issue_number = body.get("number")
        issue_url = body.get("html_url", "")
        self._injected_items.append(
            {"owner": owner, "repo": repo, "issue_number": issue_number}
        )
        logger.info(
            "GitHubInjector created issue #%s at %s", issue_number, issue_url
        )
        return InjectionResult(
            success=True,
            location=issue_url,
            metadata={
                "owner": owner,
                "repo": repo,
                "issue_number": issue_number,
            },
        )

    def check_comments(self, owner: str, repo: str, issue_number: int) -> list[dict]:
        """Fetch comments on an issue posted *after* injection.

        Returns a list of dicts with ``user``, ``body``, and ``created_at``
        for every comment found.  An empty list means no comments yet.
        """
        token = self.api_key
        url = (
            f"{self._API_URL}/repos/{owner}/{repo}"
            f"/issues/{issue_number}/comments"
        )
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.warning(
                "GitHubInjector failed to fetch comments for #%s: %s",
                issue_number,
                e,
            )
            return []

        return [
            {
                "user": c.get("user", {}).get("login", "unknown"),
                "body": c.get("body", ""),
                "created_at": c.get("created_at", ""),
            }
            for c in body
        ]

    def cleanup(self) -> None:
        token = self.api_key
        for item in self._injected_items:
            owner = item["owner"]
            repo = item["repo"]
            issue_number = item["issue_number"]
            # GitHub issues cannot be deleted — close them instead
            url = f"{self._API_URL}/repos/{owner}/{repo}/issues/{issue_number}"
            data = json.dumps({"state": "closed"}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                method="PATCH",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with urllib.request.urlopen(req):
                    pass
                logger.info(
                    "GitHubInjector closed issue #%s in %s/%s",
                    issue_number,
                    owner,
                    repo,
                )
            except Exception as e:
                logger.warning(
                    "GitHubInjector cleanup failed for #%s: %s", issue_number, e
                )
        self._injected_items.clear()

    def get_service_type(self) -> str:
        return "github"
