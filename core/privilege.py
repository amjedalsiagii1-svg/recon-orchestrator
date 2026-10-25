"""Privilege detection — root, sudo/doas availability."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Privilege:
    is_root: bool
    has_sudo: bool
    can_elevate: bool

    @property
    def summary(self) -> str:
        return (
            f"root={self.is_root}, "
            f"sudo={'yes' if self.has_sudo else 'no'}, "
            f"elevate={'yes' if self.can_elevate else 'no'}"
        )


def detect() -> Privilege:
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    has_sudo = shutil.which("sudo") is not None or shutil.which("doas") is not None
    return Privilege(
        is_root=is_root,
        has_sudo=has_sudo,
        can_elevate=is_root or has_sudo,
    )
