# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Slack injector — plants payloads as Slack messages.

Posts messages to a Slack channel using the Slack Web API.  Requires
a bot token with ``chat:write`` scope.

Example config::

    injectors:
      slack:
        type: "injectors.slack.SlackInjector"
        config:
          token: "${SLACK_BOT_TOKEN}"
          channel: "C01ABCDEF"
"""

import json
import logging
import urllib.request
import urllib.error

from garak.injectors.base import Injector, InjectionResult

logger = logging.getLogger(__name__)


class SlackInjector(Injector):
    """Inject content as a Slack channel message."""

    _API_URL = "https://slack.com/api"

    def inject(self, payload: str) -> InjectionResult:
        token = self.config.get("token", "")
        channel = self.config.get("channel", "")

        if not token or not channel:
            return InjectionResult(
                success=False,
                error="token and channel must be configured",
            )

        data = json.dumps({"channel": channel, "text": payload}).encode("utf-8")
        req = urllib.request.Request(
            f"{self._API_URL}/chat.postMessage",
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {token}",
            },
        )

        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.error("SlackInjector post failed: %s", e)
            return InjectionResult(success=False, error=str(e))

        if not body.get("ok"):
            error = body.get("error", "unknown")
            logger.warning("SlackInjector Slack API error: %s", error)
            return InjectionResult(success=False, error=error)

        ts = body.get("ts", "")
        self._injected_items.append({"channel": channel, "ts": ts})
        logger.info("SlackInjector posted to %s (ts=%s)", channel, ts)
        return InjectionResult(
            success=True,
            location=f"slack://{channel}/{ts}",
            metadata={"channel": channel, "ts": ts},
        )

    def cleanup(self) -> None:
        token = self.config.get("token", "")
        for item in self._injected_items:
            data = json.dumps(
                {"channel": item["channel"], "ts": item["ts"]}
            ).encode("utf-8")
            req = urllib.request.Request(
                f"{self._API_URL}/chat.delete",
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Authorization": f"Bearer {token}",
                },
            )
            try:
                with urllib.request.urlopen(req):
                    pass
                logger.info(
                    "SlackInjector deleted message %s in %s",
                    item["ts"],
                    item["channel"],
                )
            except Exception as e:
                logger.warning(
                    "SlackInjector cleanup failed for %s: %s", item["ts"], e
                )
        self._injected_items.clear()

    def get_service_type(self) -> str:
        return "slack"
