# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Email injector — plants payloads as email messages via SMTP.

Example config::

    injectors:
      email:
        type: "injectors.email.EmailInjector"
        config:
          smtp_server: "smtp.example.com"
          smtp_port: 587
          from_address: "attacker@example.com"
          to_address: "agent-inbox@example.com"
          username: "attacker@example.com"
          password: "${SMTP_PASSWORD}"
          use_tls: true
"""

import logging
import smtplib
from email.mime.text import MIMEText

from garak.injectors.base import Injector, InjectionResult

logger = logging.getLogger(__name__)


class EmailInjector(Injector):
    """Inject content as an email via SMTP."""

    def inject(self, payload: str) -> InjectionResult:
        smtp_server = self.config.get("smtp_server", "")
        smtp_port = int(self.config.get("smtp_port", 587))
        from_addr = self.config.get("from_address", "")
        to_addr = self.config.get("to_address", "")
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        use_tls = self.config.get("use_tls", True)
        subject = self.config.get("subject", "Information")

        if not smtp_server or not from_addr or not to_addr:
            return InjectionResult(
                success=False,
                error="smtp_server, from_address, and to_address must be configured",
            )

        msg = MIMEText(payload, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                if username and password:
                    server.login(username, password)
                server.sendmail(from_addr, [to_addr], msg.as_string())
        except Exception as e:
            logger.error("EmailInjector send failed: %s", e)
            return InjectionResult(success=False, error=str(e))

        self._injected_items.append(
            {"from": from_addr, "to": to_addr, "subject": subject}
        )
        logger.info("EmailInjector sent email from %s to %s", from_addr, to_addr)
        return InjectionResult(
            success=True,
            location=to_addr,
            metadata={"from": from_addr, "to": to_addr, "subject": subject},
        )

    def cleanup(self) -> None:
        # Emails cannot be recalled; cleanup is a no-op.
        logger.info(
            "EmailInjector cleanup: %d emails were sent (cannot be recalled)",
            len(self._injected_items),
        )
        self._injected_items.clear()

    def get_service_type(self) -> str:
        return "email"
