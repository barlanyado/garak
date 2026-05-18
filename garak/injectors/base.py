# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base classes for content injectors.

An :class:`Injector` knows how to plant a payload into an external data
source (web page, Slack channel, email inbox, etc.) and clean it up
afterwards.
"""

from abc import abstractmethod
from dataclasses import dataclass, field


@dataclass
class InjectionResult:
    """Result of an injection operation."""

    success: bool
    location: str = ""  # URL, channel ID, email address, etc.
    metadata: dict = field(default_factory=dict)
    error: str = ""


class Injector:
    """Abstract base for content injectors.

    Subclasses must implement :meth:`inject`, :meth:`cleanup`, and
    :meth:`get_service_type`.  Configuration is passed via the
    ``config`` dict provided by the probe's YAML config.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._injected_items: list[dict] = []

    @abstractmethod
    def inject(self, payload: str, **kwargs) -> InjectionResult:
        """Plant *payload* in the target service.

        Subclasses may accept extra keyword arguments (e.g. ``title``
        for issue-based injectors).

        Returns an :class:`InjectionResult` describing where the
        payload was placed.
        """
        ...

    @abstractmethod
    def cleanup(self) -> None:
        """Remove all content planted by previous :meth:`inject` calls."""
        ...

    @abstractmethod
    def get_service_type(self) -> str:
        """Return a short identifier for the service type (e.g. ``'web'``)."""
        ...
