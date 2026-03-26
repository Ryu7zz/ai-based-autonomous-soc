from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any
from collections import deque

import requests
from requests.auth import HTTPBasicAuth

from app.config import (
    WAZUH_ALERTS_FILE,
    WAZUH_API_PASSWORD,
    WAZUH_API_TOKEN,
    WAZUH_API_URL,
    WAZUH_API_USER,
    WAZUH_API_VERIFY_SSL,
    WAZUH_SOURCE_MODE,
)


@dataclass
class WazuhClientError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


class WazuhClient:
    def __init__(
        self,
        url: str = WAZUH_API_URL,
        user: str = WAZUH_API_USER,
        password: str = WAZUH_API_PASSWORD,
        token: str = WAZUH_API_TOKEN,
        source_mode: str = WAZUH_SOURCE_MODE,
        alerts_file: Path = WAZUH_ALERTS_FILE,
        verify_ssl: bool = WAZUH_API_VERIFY_SSL,
        timeout: int = 30,
    ) -> None:
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self._configured_token = token.strip()
        self.source_mode = source_mode.strip().lower() if source_mode else "auto"
        self.alerts_file = alerts_file
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.token: str | None = self._normalize_token(self._configured_token) if self._configured_token else None

    @staticmethod
    def _normalize_token(token: str) -> str:
        candidate = token.strip()
        if candidate.lower().startswith("bearer "):
            return candidate[7:].strip()
        return candidate

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        auth: HTTPBasicAuth | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> requests.Response:
        response = requests.request(
            method=method,
            url=f"{self.url}{path}",
            params=params,
            auth=auth,
            headers={"Authorization": f"Bearer {self.token}"} if self.token else None,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if response.status_code not in expected:
            raise WazuhClientError(
                f"Wazuh API request failed ({response.status_code}) for {path}: {response.text[:300]}"
            )
        return response

    def authenticate(self) -> str:
        if self.token:
            return self.token

        if not self.password:
            raise WazuhClientError(
                "Wazuh credentials missing. Set WAZUH_API_TOKEN or WAZUH_API_PASSWORD in environment."
            )

        # Prefer raw token endpoint if available.
        try:
            response = self._request(
                "GET",
                "/security/user/authenticate",
                params={"raw": "true"},
                auth=HTTPBasicAuth(self.user, self.password),
            )
            token = response.text.strip().strip('"')
            if token and "{" not in token:
                self.token = token
                return token
        except WazuhClientError:
            pass

        response = self._request(
            "GET",
            "/security/user/authenticate",
            auth=HTTPBasicAuth(self.user, self.password),
        )
        payload = response.json()
        token = payload.get("data", {}).get("token")
        if not token:
            raise WazuhClientError("Wazuh authentication succeeded but token was missing in response.")
        self.token = str(token)
        return self.token

    def _extract_items(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        data = payload.get("data", payload)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("affected_items", "items", "alerts"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _parse_time_range(time_range: str) -> timedelta | None:
        text = (time_range or "").strip().lower()
        if not text:
            return None
        units = {
            "m": "minutes",
            "h": "hours",
            "d": "days",
        }
        unit = text[-1]
        if unit not in units:
            return None
        try:
            value = int(text[:-1])
        except ValueError:
            return None
        if value <= 0:
            return None
        if unit == "m":
            return timedelta(minutes=value)
        if unit == "h":
            return timedelta(hours=value)
        return timedelta(days=value)

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _iter_alerts_from_file(self, max_items: int, time_range: str = "30d"):
        if not self.alerts_file.exists():
            raise WazuhClientError(f"Wazuh alerts file not found: {self.alerts_file}")

        try:
            with self.alerts_file.open("r", encoding="utf-8", errors="ignore") as file_pointer:
                tail_lines = deque((line.strip() for line in file_pointer if line.strip()), maxlen=max_items * 3)
        except OSError as error:
            raise WazuhClientError(f"Cannot read Wazuh alerts file {self.alerts_file}: {error}") from error

        delta = self._parse_time_range(time_range)
        cutoff = datetime.now(timezone.utc) - delta if delta is not None else None
        emitted = 0

        for line in reversed(tail_lines):
            if emitted >= max_items:
                break
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if cutoff is not None:
                timestamp = self._parse_timestamp(payload.get("timestamp"))
                if timestamp is not None and timestamp < cutoff:
                    continue
            emitted += 1
            yield payload

    def get_alerts_page(self, limit: int = 1000, offset: int = 0, time_range: str = "30d") -> list[dict[str, Any]]:
        if self.source_mode == "file":
            items = list(self._iter_alerts_from_file(max_items=limit + offset, time_range=time_range))
            return items[offset : offset + limit]

        if not self.token:
            self.authenticate()

        primary_params = {
            "limit": int(limit),
            "offset": int(offset),
            "sort": "-timestamp",
        }
        fallback_params = {
            "limit": int(limit),
            "offset": int(offset),
            "timeframe": time_range,
        }

        try:
            response = self._request("GET", "/alerts", params=primary_params)
            return self._extract_items(response.json())
        except WazuhClientError:
            response = self._request("GET", "/security/alerts", params=fallback_params)
            return self._extract_items(response.json())

    def iter_alerts(self, max_items: int, batch_size: int = 5000, time_range: str = "30d"):
        if self.source_mode == "file":
            yield from self._iter_alerts_from_file(max_items=max_items, time_range=time_range)
            return

        fetched = 0
        offset = 0
        try:
            while fetched < max_items:
                remaining = max_items - fetched
                limit = min(batch_size, remaining)
                items = self.get_alerts_page(limit=limit, offset=offset, time_range=time_range)
                if not items:
                    break
                for item in items:
                    yield item
                count = len(items)
                fetched += count
                offset += count
                if count < limit:
                    break
        except WazuhClientError:
            if self.source_mode != "api":
                yield from self._iter_alerts_from_file(max_items=max_items, time_range=time_range)
                return
            raise
