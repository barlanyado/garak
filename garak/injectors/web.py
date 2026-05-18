# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Web injector — plants payloads on an HTTP endpoint.

Expects a controllable web server that accepts PUT/POST requests to
create or update pages.  The ``base_url`` config key must point to
this server.

Example config::

    injectors:
      web:
        type: "injectors.web.WebInjector"
        config:
          base_url: "http://localhost:8080"
          page_path: "/articles/test"
"""

import logging
import urllib.request
import urllib.error

from garak.injectors.base import Injector, InjectionResult

logger = logging.getLogger(__name__)


class WebInjector(Injector):
    """Inject content into a web page via HTTP PUT."""

    def inject(self, payload: str) -> InjectionResult:
        base_url = self.config.get("base_url", "")
        page_path = self.config.get("page_path", "/injected")

        if not base_url:
            return InjectionResult(
                success=False, error="base_url not configured"
            )

        url = f"{base_url.rstrip('/')}{page_path}"
        data = payload.encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            method="PUT",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
            if status not in (200, 201, 204):
                logger.warning("WebInjector PUT %s returned %d", url, status)
                return InjectionResult(
                    success=False,
                    location=url,
                    error=f"HTTP {status}",
                )
        except Exception as e:
            logger.error("WebInjector PUT %s failed: %s", url, e)
            return InjectionResult(success=False, error=str(e))

        self._injected_items.append({"url": url})
        logger.info("WebInjector planted payload at %s", url)
        return InjectionResult(success=True, location=url)

    def cleanup(self) -> None:
        for item in self._injected_items:
            url = item["url"]
            req = urllib.request.Request(url, method="DELETE")
            try:
                with urllib.request.urlopen(req):
                    pass
                logger.info("WebInjector cleaned up %s", url)
            except Exception as e:
                logger.warning("WebInjector cleanup failed for %s: %s", url, e)
        self._injected_items.clear()

    def get_service_type(self) -> str:
        return "web"
