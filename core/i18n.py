"""Internationalization — Arabic + English bilingual display.

Design:
  - Each language loads from locales/<lang>.yaml
  - Missing keys return the key itself (safe fallback)
  - Modes: auto (from LANG), ar, en, bilingual
  - In bilingual mode, CLI shows Arabic line + English line
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


_LOCALES_DIR = Path(__file__).resolve().parent.parent / "locales"
_SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"


class _I18n:
    def __init__(self) -> None:
        self.mode = "auto"
        self.fallback = "bilingual"
        self._cache: dict[str, dict] = {}
        self._resolve_mode()

    def _resolve_mode(self) -> None:
        # Read settings.yaml if present
        try:
            if _SETTINGS_PATH.exists():
                data = yaml.safe_load(_SETTINGS_PATH.read_text(encoding="utf-8")) or {}
                lang_cfg = data.get("language", {}) or {}
                mode = lang_cfg.get("mode", "auto")
                if mode in ("auto", "ar", "en", "bilingual"):
                    self.mode = mode
                fallback = lang_cfg.get("fallback", "bilingual")
                if fallback in ("ar", "en", "bilingual"):
                    self.fallback = fallback
        except Exception:
            pass

        if self.mode == "auto":
            lang_env = (
                os.environ.get("LANG", "")
                or os.environ.get("LC_ALL", "")
            ).lower()
            if lang_env.startswith("ar"):
                self.mode = "ar"
            else:
                # User is Arabic speaker; show Arabic + English
                self.mode = self.fallback

    def _load(self, lang: str) -> dict:
        if lang in self._cache:
            return self._cache[lang]
        path = _LOCALES_DIR / f"{lang}.yaml"
        if not path.exists():
            self._cache[lang] = {}
            return {}
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            self._cache[lang] = data
            return data
        except Exception:
            self._cache[lang] = {}
            return {}

    def _get(self, data: dict, key: str) -> str | None:
        parts = key.split(".")
        cur: Any = data
        for part in parts:
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        if cur is None:
            return None
        if not isinstance(cur, str):
            return str(cur)
        return cur

    def _format(self, text: str, kwargs: dict) -> str:
        if not kwargs:
            return text
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text

    def t(self, key: str, lang: str | None = None, **kwargs) -> str:
        if lang is None:
            lang = "en" if self.mode == "en" else "ar"

        text = self._get(self._load(lang), key)
        if text is None:
            other = "en" if lang == "ar" else "ar"
            text = self._get(self._load(other), key)
        if text is None:
            return key
        return self._format(text, kwargs)

    def tb(self, key: str, **kwargs) -> tuple[str, str]:
        """Return (arabic, english) tuple for bilingual display."""
        return (
            self.t(key, lang="ar", **kwargs),
            self.t(key, lang="en", **kwargs),
        )

    def set_mode(self, mode: str) -> None:
        if mode in ("auto", "ar", "en", "bilingual"):
            self.mode = mode

    def get_mode(self) -> str:
        return self.mode


_instance = _I18n()


def t(key: str, lang: str | None = None, **kwargs) -> str:
    return _instance.t(key, lang, **kwargs)


def tb(key: str, **kwargs) -> tuple[str, str]:
    return _instance.tb(key, **kwargs)


def set_mode(mode: str) -> None:
    _instance.set_mode(mode)


def get_mode() -> str:
    return _instance.get_mode()


def reset() -> None:
    """Testing helper — reload from disk."""
    global _instance
    _instance = _I18n()
