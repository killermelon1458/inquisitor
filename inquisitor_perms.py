from __future__ import annotations

import json
import os
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, List

# ---------------------------
# Role classes (defaults)
# ---------------------------

VALID_PERMS = {
    # command perms
    "weather_clear",
    "kick",
    "whitelist",
    "unwhitelist",
    "ban",
    "bot_message",
    "admin_message",
    "set_role",
    "set_permission",
    "set_blockers",
    "reload_perms",

    # generic
    "owner",
}

VALID_BLOCKERS = {"bannable", "kickable", "unwhitelistable"}


@dataclass
class Role:
    role_name: str = "Guest"
    perms: Dict[str, bool] = field(default_factory=dict)

    # inherited data members (start at Guest)
    usernames: List[str] = field(default_factory=list)
    uuids: List[str] = field(default_factory=list)

    def can(self, perm: str) -> bool:
        return bool(self.perms.get(perm, False))


def _merge(a: Dict[str, bool], b: Dict[str, bool]) -> Dict[str, bool]:
    out = dict(a)
    out.update(b)
    return out


class Guest(Role):
    def __init__(self):
        super().__init__(
            role_name="Guest",
            perms={
                "weather_clear": True,
                "kick": False,
                "whitelist": False,
                "unwhitelist": False,
                "ban": False,
                "bot_message": False,
                "admin_message": False,
                "set_role": False,
                "set_permission": False,
                "set_blockers": False,
                "reload_perms": False,
                "owner": False,
            },
        )


class Member(Guest):
    def __init__(self):
        super().__init__()
        self.role_name = "Member"
        self.perms = _merge(self.perms, {"kick": True})


class Mod(Member):
    def __init__(self):
        super().__init__()
        self.role_name = "Mod"
        self.perms = _merge(self.perms, {"whitelist": True, "unwhitelist": True})


class Owner(Mod):
    def __init__(self):
        super().__init__()
        self.role_name = "Owner"
        self.perms = _merge(self.perms, {
            "ban": True,
            "bot_message": True,
            "admin_message": True,
            "set_role": True,
            "set_permission": True,
            "set_blockers": True,
            "reload_perms": True,
            "owner": True,  # generic future flag
        })


ROLE_CLASSES = {
    "guest": Guest,
    "member": Member,
    "mod": Mod,
    "owner": Owner,
}


# ---------------------------
# Helpers
# ---------------------------

_NOT_FOUND_KEYWORDS = (
    "does not exist",
    "unknown player",
    "no such player",
    "couldn't find profile",
    "couldnt find profile",
    "couldn't find any profile",
    "couldnt find any profile",
    "could not find",
    "not found",
)


def looks_like_not_found(rcon_result: str | None) -> bool:
    s = (rcon_result or "").lower()
    return any(k in s for k in _NOT_FOUND_KEYWORDS)


def normalize_ign_key(name: str) -> str:
    return (name or "").strip().lower()


# ---------------------------
# Permission Manager
# ---------------------------

class PermissionManager:
    def __init__(self, path: str | pathlib.Path, usercache_path: str | pathlib.Path):
        self.path = pathlib.Path(path)
        self.usercache_path = pathlib.Path(usercache_path)

        self.data: Dict[str, Any] = {}
        self.users: Dict[str, Role] = {}          # discord_id -> Role instance
        self.blockers: Dict[str, Dict[str, bool]] = {}  # ign_lower -> blockers dict
        self.ign_to_discord: Dict[str, str] = {}  # ign_lower -> discord_id

    # ---------- Load/Save ----------

    def _default_data(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "users": {},
            "blockers": {},
        }

    def load(self) -> None:
        if not self.path.exists():
            self.data = self._default_data()
            self._rehydrate()
            self.save()
            return

        raw = self.path.read_text(encoding="utf-8")
        self.data = json.loads(raw) if raw.strip() else self._default_data()

        # Ensure required keys exist
        if "users" not in self.data: self.data["users"] = {}
        if "blockers" not in self.data: self.data["blockers"] = {}
        if "schema_version" not in self.data: self.data["schema_version"] = 1

        self._rehydrate()

    def save(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def _rehydrate(self) -> None:
        self.users.clear()
        self.blockers = {}
        self.ign_to_discord.clear()

        # Load blockers
        for ign_lower, b in (self.data.get("blockers") or {}).items():
            if not isinstance(b, dict):
                continue
            # only accept known blocker keys
            clean = {k: bool(b.get(k, True)) for k in VALID_BLOCKERS}
            self.blockers[str(ign_lower)] = clean

        # Load users
        users = self.data.get("users") or {}
        for discord_id, u in users.items():
            if not isinstance(u, dict):
                continue
            role_name = str(u.get("role", "Guest")).strip().lower()
            cls = ROLE_CLASSES.get(role_name, Guest)
            role = cls()

            # usernames/uuids arrays (inherited members)
            role.usernames = list(u.get("usernames") or [])
            role.uuids = list(u.get("uuids") or [])

            # apply overrides
            overrides = u.get("overrides") or {}
            if isinstance(overrides, dict):
                for k, v in overrides.items():
                    if k in VALID_PERMS:
                        role.perms[k] = bool(v)

            self.users[str(discord_id)] = role

        # Build reverse map + enforce owner auto-protect
        self._rebuild_ign_maps_and_owner_protect()

    def _rebuild_ign_maps_and_owner_protect(self) -> None:
        self.ign_to_discord.clear()

        # 1) reverse map
        for did, role in self.users.items():
            for ign in role.usernames:
                key = normalize_ign_key(ign)
                if not key:
                    continue
                self.ign_to_discord[key] = did

        # 2) owner default: owners are unbannable + unwhitelistable (for their registered IGNs)
        changed = False
        for did, role in self.users.items():
            if role.role_name.lower() != "owner":
                continue
            for ign in role.usernames:
                key = normalize_ign_key(ign)
                if not key:
                    continue
                b = self.blockers.get(key) or {"bannable": True, "kickable": True, "unwhitelistable": True}
                # enforce defaults
                if b.get("bannable", True) is not False:
                    b["bannable"] = False
                    changed = True
                if b.get("unwhitelistable", True) is not False:
                    b["unwhitelistable"] = False
                    changed = True
                self.blockers[key] = b

        if changed:
            # mirror back to data + persist later (caller decides)
            self.data["blockers"] = self.blockers

    # ---------- Guild bootstrap ----------

    async def ensure_all_members_have_records(self, guild) -> bool:
        """
        Ensure every discord member in the guild exists in JSON (default Guest).
        Returns True if changes were made.
        """
        changed = False
        users = self.data.setdefault("users", {})

        # fetch members if possible; fallback to cached
        members = []
        try:
            async for m in guild.fetch_members(limit=None):
                members.append(m)
        except Exception:
            members = list(getattr(guild, "members", []) or [])

        for m in members:
            did = str(m.id)
            if did not in users:
                users[did] = {
                    "role": "Guest",
                    "overrides": {},
                    "usernames": [],
                    "uuids": [],
                }
                changed = True

        if changed:
            self._rehydrate()
        return changed

    # ---------- Permission checks ----------

    def can(self, discord_id: int | str, perm: str) -> bool:
        role = self.users.get(str(discord_id))
        if not role:
            return False
        if perm not in VALID_PERMS:
            return False
        return role.can(perm)

    def get_role(self, discord_id: int | str) -> str:
        role = self.users.get(str(discord_id))
        return role.role_name if role else "Guest"

    # ---------- User lookups ----------

    def get_registered_igns(self, discord_id: int | str) -> List[str]:
        role = self.users.get(str(discord_id))
        return list(role.usernames) if role else []

    def lookup_discord_by_ign(self, ign: str) -> Optional[str]:
        return self.ign_to_discord.get(normalize_ign_key(ign))

    # ---------- Blockers ----------

    def get_blocker(self, ign: str, blocker: str) -> bool:
        """
        Returns True if allowed, False if blocked.
        Defaults to True (allowed) if not set.
        """
        if blocker not in VALID_BLOCKERS:
            return True
        key = normalize_ign_key(ign)
        b = self.blockers.get(key)
        if not b:
            return True
        return bool(b.get(blocker, True))

    def set_blocker(self, ign: str, blocker: str, value: bool) -> None:
        if blocker not in VALID_BLOCKERS:
            raise ValueError(f"Unknown blocker: {blocker}")
        key = normalize_ign_key(ign)
        b = self.blockers.get(key) or {"bannable": True, "kickable": True, "unwhitelistable": True}
        b[blocker] = bool(value)
        self.blockers[key] = b
        self.data.setdefault("blockers", {})[key] = b
        # keep owner protections intact
        self._rebuild_ign_maps_and_owner_protect()

    # ---------- Mutators (apply immediately + persist) ----------

    def set_role(self, discord_id: int | str, role_name: str) -> None:
        role_name_clean = str(role_name).strip().lower()
        if role_name_clean not in ROLE_CLASSES:
            raise ValueError(f"Unknown role: {role_name}")

        did = str(discord_id)
        users = self.data.setdefault("users", {})
        u = users.get(did) or {"role": "Guest", "overrides": {}, "usernames": [], "uuids": []}
        u["role"] = ROLE_CLASSES[role_name_clean]().role_name
        users[did] = u

        self._rehydrate()
        self.save()

    def set_permission(self, discord_id: int | str, perm: str, value: bool) -> None:
        if perm not in VALID_PERMS:
            raise ValueError(f"Unknown permission: {perm}")

        did = str(discord_id)
        users = self.data.setdefault("users", {})
        u = users.get(did) or {"role": "Guest", "overrides": {}, "usernames": [], "uuids": []}
        overrides = u.setdefault("overrides", {})
        overrides[perm] = bool(value)
        users[did] = u

        self._rehydrate()
        self.save()

    # ---------- Usercache + IGN registration ----------

    def _read_usercache(self) -> List[Dict[str, Any]]:
        if not self.usercache_path.exists():
            return []
        try:
            raw = self.usercache_path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else []
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def lookup_usercache_exact(self, ign_exact: str) -> Optional[str]:
        """
        Return UUID for exact-case name match from usercache.json.
        """
        for entry in self._read_usercache():
            name = entry.get("name")
            uuid = entry.get("uuid")
            if name == ign_exact and isinstance(uuid, str) and uuid.strip():
                return uuid.strip()
        return None

    def ign_in_use_by_other(self, ign: str, discord_id: int | str) -> Optional[str]:
        """
        Returns other discord_id if IGN is already registered to someone else.
        Comparison is case-insensitive to prevent collisions.
        """
        key = normalize_ign_key(ign)
        if not key:
            return None
        existing = self.ign_to_discord.get(key)
        if existing and existing != str(discord_id):
            return existing
        return None

    def set_user_igns(self, discord_id: int | str, usernames: List[str], uuids: List[str]) -> None:
        did = str(discord_id)
        users = self.data.setdefault("users", {})
        u = users.get(did) or {"role": "Guest", "overrides": {}, "usernames": [], "uuids": []}

        u["usernames"] = list(usernames)
        u["uuids"] = list(uuids)
        users[did] = u

        self._rehydrate()
        self.save()

    def append_user_ign(self, discord_id: int | str, ign: str, uuid: str) -> None:
        did = str(discord_id)
        users = self.data.setdefault("users", {})
        u = users.get(did) or {"role": "Guest", "overrides": {}, "usernames": [], "uuids": []}

        names = list(u.get("usernames") or [])
        uuids = list(u.get("uuids") or [])

        names.append(ign)
        uuids.append(uuid)

        u["usernames"] = names
        u["uuids"] = uuids
        users[did] = u

        self._rehydrate()
        self.save()
