#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import discord
from discord.ext import commands

from inquisitor_token import INQUISITOR_TOKEN, GUILD_ID, PREFIX

VERBOSE = "--verbose" in sys.argv
CHUNK_TIMEOUT_SEC = 8  # don't hang forever


def jdump(x: Any) -> str:
    return json.dumps(x, indent=2, ensure_ascii=False, sort_keys=True)


intents = discord.Intents.default()
intents.members = True          # match inquisitor style
intents.message_content = False # slash commands don't need this

bot = commands.Bot(command_prefix=PREFIX, intents=intents)


async def rest_get(bot: commands.Bot, method: str, path: str, **kwargs):
    # Low-level REST call so you can see “raw Discord format”
    from discord.http import Route
    return await bot.http.request(Route(method, path), **kwargs)


@bot.event
async def on_ready():
    print("\n=== DISCORD DUMP V2 START ===")
    print(f"Bot user: {bot.user} (id={bot.user.id})")
    print(f"GUILD_ID: {GUILD_ID}")
    print(f"intents: members={bot.intents.members} message_content={bot.intents.message_content}")

    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        print("[CACHE] get_guild() returned None (not cached yet). Trying fetch_guild()...")
        try:
            g = await bot.fetch_guild(GUILD_ID)
            print(f"[REST] fetch_guild OK: name={g.name!r} id={g.id}")
        except Exception as e:
            print(f"[FAIL] fetch_guild failed: {type(e).__name__}: {e}")
            await bot.close()
            return
    else:
        print(f"[CACHE] guild cached: name={guild.name!r} id={guild.id}")

    # ----------------------------
    # Roles (cache first, then raw REST)
    # ----------------------------
    if guild is not None:
        print("\n--- CACHED ROLES ---")
        for r in sorted(guild.roles, key=lambda x: x.position, reverse=True):
            print(f"role: name={r.name!r} id={r.id} pos={r.position} managed={r.managed}")

    print("\n--- RAW ROLES (REST JSON) ---")
    try:
        raw_roles = await rest_get(bot, "GET", "/guilds/{guild_id}/roles", guild_id=GUILD_ID)
        print(f"raw roles count: {len(raw_roles)}")
        print(jdump(raw_roles))
        with open("discord_dump_roles.json", "w", encoding="utf-8") as f:
            f.write(jdump(raw_roles) + "\n")
        print("[SAVED] discord_dump_roles.json")
    except Exception as e:
        print(f"[FAIL] roles REST fetch failed: {type(e).__name__}: {e}")

    # ----------------------------
    # Members (try chunk with timeout, then fetch via REST)
    # ----------------------------
    if guild is not None:
        print("\n--- MEMBER CACHE CHUNK (timeout protected) ---")
        try:
            await asyncio.wait_for(guild.chunk(cache=True), timeout=CHUNK_TIMEOUT_SEC)
            print("[OK] guild.chunk() finished")
        except asyncio.TimeoutError:
            print(f"[WARN] guild.chunk() timed out after {CHUNK_TIMEOUT_SEC}s (common gateway chunk hang)")
        except Exception as e:
            print(f"[WARN] guild.chunk() failed: {type(e).__name__}: {e}")

        print("\n--- CACHED MEMBERS (after chunk attempt) ---")
        print(f"cached member count: {len(guild.members)}")
        for m in sorted(guild.members, key=lambda x: (x.bot, x.display_name.lower())):
            role_names = [rr.name for rr in m.roles if not rr.is_default()]
            print(f"member: display={m.display_name!r} id={m.id} bot={m.bot} roles={role_names}")

    print("\n--- RAW MEMBERS (REST JSON) ---")
    try:
        # Paginate /members with 'after'
        all_members = []
        after = 0
        limit = 1000

        while True:
            chunk = await rest_get(
                bot,
                "GET",
                "/guilds/{guild_id}/members",
                guild_id=GUILD_ID,
                params={"limit": limit, "after": after},
            )
            if not chunk:
                break
            all_members.extend(chunk)
            after = int(chunk[-1]["user"]["id"])
            if VERBOSE:
                print(f"[REST] got {len(chunk)} members (total={len(all_members)}) after={after}")
            if len(chunk) < limit:
                break

        print(f"raw members count: {len(all_members)}")

        with open("discord_dump_members.json", "w", encoding="utf-8") as f:
            f.write(jdump(all_members) + "\n")
        print("[SAVED] discord_dump_members.json")

        # Print a small preview so terminal isn't destroyed
        preview = all_members[:25]
        print("\nRAW MEMBERS PREVIEW (first 25):")
        print(jdump(preview))

    except discord.Forbidden as e:
        print(f"[FAIL] members REST fetch forbidden: {e}")
        print("This can happen if Discord requires Server Members Intent for List Guild Members.")
    except discord.HTTPException as e:
        print(f"[FAIL] members REST fetch HTTPException: status={e.status} code={getattr(e, 'code', None)} text={e.text}")
    except Exception as e:
        print(f"[FAIL] members REST fetch failed: {type(e).__name__}: {e}")

    print("\n=== DISCORD DUMP V2 END ===\n")
    await bot.close()


def main():
    bot.run(INQUISITOR_TOKEN)


if __name__ == "__main__":
    main()

