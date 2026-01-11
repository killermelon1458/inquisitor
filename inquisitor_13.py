# ==== Logging & Verbose bootstrap (must be first) ====
from __future__ import annotations
import os, sys, argparse, time, faulthandler, threading, contextlib, traceback, functools
from logging.handlers import RotatingFileHandler
import logging

# Parse VERBOSE from argv/env (both supported)
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--verbose", action="store_true")
_env_verbose = os.environ.get("VERBOSE", "").strip()
_argv_verbose = any(a.strip().lower() in ("--verbose", "verbose", "verbose=1", "verbose=true") for a in sys.argv[1:])
_args, _unknown = _parser.parse_known_args()
VERBOSE: bool = bool(_args.verbose or _argv_verbose or _env_verbose in ("1","true","True"))

def apply_logger_levels():
    """Retune logger levels when VERBOSE changes."""
    lvl = logging.DEBUG if VERBOSE else logging.INFO
    log.setLevel(lvl)
    logging.getLogger().setLevel(lvl)  # root
    logging.getLogger("discord").setLevel(lvl)
    logging.getLogger("discord.gateway").setLevel(lvl)
    logging.getLogger("aiohttp.client").setLevel(lvl)
    vlog("Logger levels applied (VERBOSE=%s)", VERBOSE)

def set_verbose_runtime(new_value: bool, source: str = "runtime") -> None:
    """Flip global VERBOSE live and retune loggers."""
    global VERBOSE
    old = VERBOSE
    VERBOSE = bool(new_value)
    log.info("VERBOSE changed: %s -> %s (source=%s)", old, VERBOSE, source)
    apply_logger_levels()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR  = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_log_level = logging.DEBUG if VERBOSE else logging.INFO
_handlers = [
    RotatingFileHandler(os.path.join(LOG_DIR, "inquisitor.log"), maxBytes=2_000_000, backupCount=5, encoding="utf-8"),
    logging.StreamHandler(sys.stdout),
]
logging.basicConfig(level=_log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=_handlers)
log = logging.getLogger("inquisitor")

logging.getLogger("discord").setLevel(logging.DEBUG if VERBOSE else logging.INFO)
logging.getLogger("discord.gateway").setLevel(logging.DEBUG if VERBOSE else logging.INFO)
logging.getLogger("aiohttp.client").setLevel(logging.DEBUG if VERBOSE else logging.INFO)

def vlog(msg: str, *a, **k):
    """Verbose-only log (DEBUG)."""
    if VERBOSE:
        log.debug(msg, *a, **k)

def log_exceptions(where: str):
    """Decorator to always log exceptions with context."""
    def _wrap(fn):
        @functools.wraps(fn)
        async def _a(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception:
                log.exception("Unhandled exception in %s", where)
                raise
        return _a
    return _wrap

@contextlib.contextmanager
def hang_watch(label: str, seconds: float = 15.0):
    """
    If the block doesn't finish within 'seconds', dump all thread tracebacks.
    Good for pinpointing 'hangs' during blocking I/O.
    """
    def _dump():
        log.error("Timeout waiting for '%s' (>%ss). Dumping thread tracebacks...", label, seconds)
        faulthandler.dump_traceback(file=sys.stderr)
    timer = threading.Timer(seconds, _dump)
    timer.daemon = True
    timer.start()
    t0 = time.perf_counter()
    try:
        yield
    finally:
        timer.cancel()
        dt = time.perf_counter() - t0
        log.info("%s completed in %.3fs", label, dt)

print("[BOOT] inquisitor_12.py imported; starting setup...", flush=True)
log.info("=== Boot start (VERBOSE=%s) ===", VERBOSE)

# ==== imports ====
import re
import json
import socket
import pathlib
import asyncio

import discord
from discord.ext import commands
from discord import app_commands

import mc_rcon
import rcon_config
from message_manager import get_message
from inquisitor_token import INQUISITOR_TOKEN, GUILD_ID, PREFIX

# Your new perms module (same directory)
from inquisitor_perms import PermissionManager, looks_like_not_found

INQUISITOR_CHANNEL_ID = 1423093468405825616

# ---------------------------
# PATH CONFIG (EDIT THIS!)
# ---------------------------

# Permissions JSON file (auto-created if missing)
PERMS_PATH = pathlib.Path(__file__).with_name("inquisitor_perms.json")

# IMPORTANT: Set to your server's usercache.json path
# Example: "/home/minecraft/server/usercache.json"
USERCACHE_PATH = pathlib.Path("/path/to/usercache.json")

PERMS = PermissionManager(PERMS_PATH, USERCACHE_PATH)
PERMS.load()

# --- Init RCON ---
with hang_watch("RCON set_rcon_config (connect-on-init?)", seconds=15):
    log.info("RCON: applying config host=%s port=%s", getattr(rcon_config, "HOST", "?"), getattr(rcon_config, "PORT", "?"))
    mc_rcon.set_rcon_config(rcon_config.HOST, rcon_config.PORT, rcon_config.PASSWORD)
log.info("RCON: config applied")

# --- Discord Bot ---
log.info("Discord intents: members=True, message_content=True")
intents = discord.Intents.default()
intents.members = True
intents.message_content = True

log.info("Creating bot object (prefix=%r)", PREFIX)
bot = commands.Bot(command_prefix=PREFIX, intents=intents)
tree = bot.tree

# ---------------------------
# Utilities
# ---------------------------

def _no_perm_msg(discord_user, player: str = "") -> str:
    try:
        msg = get_message("no_permission", "inquisitor_no_permission_messages.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")
    except Exception:
        return "❌ You don't have permission."

# --- Mute list (per-channel) for in-game broadcasts ---
def _load_muted_channels(filepath: str = "inquisitor_muted_channels.txt") -> set[int]:
    try:
        muted: set[int] = set()
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if not s:
                    continue
                try:
                    muted.add(int(s))
                except ValueError:
                    log.warning("Muted channels: invalid id %r in %s", s, filepath)
        return muted
    except FileNotFoundError:
        return set()

def _is_channel_muted(channel_id: int, filepath: str = "inquisitor_muted_channels.txt") -> bool:
    return channel_id in _load_muted_channels(filepath)

async def _send_ingame_maybe(channel_id: int, sender: str, text: str) -> bool:
    """
    Returns True if an in-game message was sent, False if suppressed for this channel.
    """
    if _is_channel_muted(channel_id):
        if VERBOSE:
            vlog("muted-channel: %s -> suppressing in-game broadcast: %r", channel_id, text[:120])
        return False
    await asyncio.to_thread(mc_rcon.rcon_bot_message, sender, text)
    return True

# --- Helper: choose response based on RCON result ---
def choose_message(result: str, success_file: str, discord_user, player: str, verbose: bool | None = None):
    if verbose is None: verbose = VERBOSE
    result_lower = (result or "").lower()
    if verbose:
        vlog("choose_message(result=%r, success_file=%s, user=%s, player=%s)",
             (result[:120] + "…") if result and len(result) > 120 else result,
             success_file, discord_user.name if discord_user else "?", player)

    if "rcon error" in result_lower:
        offline_keywords = ["getaddrinfo", "refused", "offline", "timed out", "10060", "failed to respond"]
        if any(keyword in result_lower for keyword in offline_keywords):
            msg = get_message("server_offline", "inquisitor_server_not_online.txt")
        else:
            msg = get_message("action_failed", "inquisitor_action_failed.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    fail_keywords = ["does not exist", "unknown player", "already whitelisted", "not whitelisted", "cannot ban", "cannot kick"]
    if any(keyword in result_lower for keyword in fail_keywords):
        msg = get_message("failed_action", "inquisitor_action_failed.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    success_keywords = ["added", "removed", "kicked", "banned", "changed", "set the weather", "cleared", "pardon", "unbanned"]
    if any(keyword in result_lower for keyword in success_keywords):
        msg = get_message("success", success_file)
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    msg = get_message("failed_action", "inquisitor_action_failed.txt")
    return msg.format(discord_user=discord_user.name, player=player or "N/A")

# ---------------------------
# Target resolution + blockers
# ---------------------------

def _find_member_by_string(guild: discord.Guild, s: str) -> discord.Member | None:
    if not guild or not s:
        return None
    raw = s.strip()

    m = re.match(r"^<@!?(\d+)>$", raw)
    if m:
        return guild.get_member(int(m.group(1)))

    if raw.isdigit():
        return guild.get_member(int(raw))

    target = raw.lower()
    hits = []
    for mem in (getattr(guild, "members", []) or []):
        if (mem.name and mem.name.lower() == target) or \
           (mem.display_name and mem.display_name.lower() == target) or \
           (getattr(mem, "global_name", None) and mem.global_name and mem.global_name.lower() == target):
            hits.append(mem)
    if len(hits) == 1:
        return hits[0]
    return None

def _blocker_for_action(action: str) -> str | None:
    a = (action or "").lower()
    if a in ("ban", "unban"):
        return "bannable"
    if a == "kick":
        return "kickable"
    if a == "unwhitelist":
        return "unwhitelistable"
    return None

async def _attempt_one_ign(action_name: str, ign: str, rcon_call_fn, reason: str = "") -> str:
    """
    Enforce blockers only if IGN is registered to someone in our system.
    """
    # if ign is registered, blockers apply
    registered_owner = PERMS.lookup_discord_by_ign(ign)
    blocker = _blocker_for_action(action_name)
    if registered_owner and blocker:
        if not PERMS.get_blocker(ign, blocker):
            return f"BLOCKED: `{ign}` is protected ({blocker}=false)."

    if action_name in ("kick", "ban") and reason:
        return await asyncio.to_thread(rcon_call_fn, ign, reason)
    return await asyncio.to_thread(rcon_call_fn, ign)

async def run_player_action(
    interaction: discord.Interaction,
    target_input: str,
    action_name: str,
    rcon_call_fn,
    success_file: str,
    reason: str = "",
    not_found_hint: str | None = None,
):
    """
    Spec:
      1) Try target_input as IGN first.
      2) If 'not found', treat it as Discord user string and try their registered IGN(s).
      3) If target IGN is registered, enforce blockers before acting.
    """
    guild = interaction.guild
    if not guild:
        await interaction.followup.send("❌ Guild context missing.", ephemeral=False)
        return

    # --- Direct IGN attempt first ---
    first_result = await _attempt_one_ign(action_name, target_input, rcon_call_fn, reason=reason)

    # Blocked response (explicit)
    if isinstance(first_result, str) and first_result.startswith("BLOCKED:"):
        await interaction.followup.send(f"❌ {first_result}", ephemeral=False)
        return

    if not looks_like_not_found(first_result):
        formatted = choose_message(first_result, success_file, interaction.user, target_input, verbose=VERBOSE)
        await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)
        await interaction.followup.send(formatted, ephemeral=False)
        return

    # --- Fallback: treat input as Discord user string ---
    member = _find_member_by_string(guild, target_input)
    if not member:
        # not found as IGN AND not a resolvable Discord user -> hint if provided
        if not_found_hint:
            await interaction.followup.send(not_found_hint, ephemeral=False)
        else:
            formatted = choose_message(first_result, success_file, interaction.user, target_input, verbose=VERBOSE)
            await interaction.followup.send(formatted, ephemeral=False)
        return

    igns = PERMS.get_registered_igns(member.id)
    if not igns:
        await interaction.followup.send(
            f"❌ `{target_input}` looks like a Discord user, but they have no registered IGN.\n"
            f"Ask them to run `/register_my_ign <IGN>` first.",
            ephemeral=False,
        )
        return

    results = []
    for ign in igns:
        r = await _attempt_one_ign(action_name, ign, rcon_call_fn, reason=reason)
        results.append((ign, r))

    lines = []
    for ign, r in results:
        if isinstance(r, str) and r.startswith("BLOCKED:"):
            lines.append(f"**{ign}** → ❌ {r}")
        else:
            msg = choose_message(r, success_file, interaction.user, ign, verbose=VERBOSE)
            lines.append(f"**{ign}** → {msg}")

    await interaction.followup.send("\n".join(lines), ephemeral=False)

# ---------------------------
# Intro message
# ---------------------------

@log_exceptions("update_inquisitor_intro")
async def update_inquisitor_intro(bot, verbose: bool | None = None):
    if verbose is None: verbose = VERBOSE
    channel = bot.get_channel(INQUISITOR_CHANNEL_ID)
    if not channel:
        log.warning("update_inquisitor_intro: channel %s not found", INQUISITOR_CHANNEL_ID)
        return

    intro_message = (
        "I am the Inquisitor. I judge, I permit, I deny. My will is law.\n\n"
        "`/weather_clear` — Fine. The skies will obey me, this once.\n"
        "`/kick <player|discord>` — Cast out, for now.\n"
        "`/whitelist <player|discord>` — I permit their entry (Java).\n"
        "`/unwhitelist <player|discord>` — Their passage is revoked (Java).\n"
        "`/bedrock_whitelist <username>` — Floodgate whitelist add.\n"
        "`/bedrock_unwhitelist <username>` — Floodgate whitelist remove.\n\n"
        "`/register_my_ign <IGN>` — Bind your Discord identity to your Minecraft name.\n"
        "`/unregister_my_ign` — Sever the binding.\n\n"
        "⚖️ Only those with authority may command me."
    )

    async for msg in channel.history(limit=50):
        if msg.author == bot.user and not msg.embeds:
            await msg.edit(content=intro_message)
            if verbose: vlog("update_inquisitor_intro: edited existing message %s", msg.id)
            return

    await channel.send(intro_message)
    if verbose: vlog("update_inquisitor_intro: sent new intro message")

# ---------------------------
# Commands
# ---------------------------

@app_commands.command(name="weather_clear", description="Clear the server weather.")
@log_exceptions("weather_clear_command")
async def weather_clear_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "weather_clear"):
        await interaction.followup.send(_no_perm_msg(interaction.user, "weather_clear"), ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_weather_clear)
    formatted = choose_message(mc_result, "inquisitor_weather_messages.txt", interaction.user, "N/A", verbose=VERBOSE)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)
    await interaction.followup.send(formatted, ephemeral=False)


@app_commands.command(name="whitelist", description="Whitelist a player (Java).")
@log_exceptions("whitelist_command")
async def whitelist_command(interaction: discord.Interaction, player: str):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "whitelist"):
        await interaction.followup.send(_no_perm_msg(interaction.user, player), ephemeral=False)
        return

    hint = "❌ No such player found. They should attempt to connect once, then try whitelisting again."
    await run_player_action(
        interaction=interaction,
        target_input=player,
        action_name="whitelist",
        rcon_call_fn=mc_rcon.rcon_whitelist,
        success_file="inquisitor_whitelist_messages.txt",
        not_found_hint=hint,
    )


@app_commands.command(name="unwhitelist", description="Remove a player from whitelist (Java).")
@log_exceptions("unwhitelist_command")
async def unwhitelist_command(interaction: discord.Interaction, player: str):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "unwhitelist"):
        await interaction.followup.send(_no_perm_msg(interaction.user, player), ephemeral=False)
        return

    await run_player_action(
        interaction=interaction,
        target_input=player,
        action_name="unwhitelist",
        rcon_call_fn=mc_rcon.rcon_unwhitelist,
        success_file="inquisitor_unwhitelist_messages.txt",
    )


@app_commands.command(name="kick", description="Kick a player.")
@log_exceptions("kick_command")
async def kick_command(interaction: discord.Interaction, player: str, reason: str = ""):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "kick"):
        await interaction.followup.send(_no_perm_msg(interaction.user, player), ephemeral=False)
        return

    await run_player_action(
        interaction=interaction,
        target_input=player,
        action_name="kick",
        rcon_call_fn=mc_rcon.rcon_kick,
        success_file="inquisitor_kick_messages.txt",
        reason=reason or "",
    )


@app_commands.command(name="ban", description="Ban a player.")
@log_exceptions("ban_command")
async def ban_command(interaction: discord.Interaction, player: str, reason: str = ""):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "ban"):
        await interaction.followup.send(_no_perm_msg(interaction.user, player), ephemeral=False)
        return

    await run_player_action(
        interaction=interaction,
        target_input=player,
        action_name="ban",
        rcon_call_fn=mc_rcon.rcon_ban,
        success_file="inquisitor_ban_messages.txt",
        reason=reason or "",
    )


@app_commands.command(name="unban", description="Unban a player.")
@log_exceptions("unban_command")
async def unban_command(interaction: discord.Interaction, player: str):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "ban"):
        await interaction.followup.send(_no_perm_msg(interaction.user, player), ephemeral=False)
        return

    async def _pardon(ign: str):
        return await asyncio.to_thread(mc_rcon._send_rcon_command, f"pardon {ign}")

    # Wrap _pardon into the same signature as run_player_action expects
    async def _pardon_call(ign: str):
        return await _pardon(ign)

    await run_player_action(
        interaction=interaction,
        target_input=player,
        action_name="unban",
        rcon_call_fn=lambda ign: mc_rcon._send_rcon_command(f"pardon {ign}"),
        success_file="inquisitor_action_failed.txt",  # choose_message uses it for success; we’ll still format below
    )


@app_commands.command(name="bot_message", description="Send a server message as Inquisitor (Owner).")
@log_exceptions("bot_message_command")
async def bot_message_command(interaction: discord.Interaction, message: str):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "bot_message"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", message)
    if not mc_result:
        await interaction.followup.send(f"✅ Sent: [Inquisitor] {message}", ephemeral=True)
    elif "RCON Error" in (mc_result or ""):
        await interaction.followup.send(f"❌ Failed to send message: {mc_result}", ephemeral=True)
    else:
        await interaction.followup.send(f"✅ Sent: [Inquisitor] {message}\n(Server said: {mc_result})", ephemeral=True)


@app_commands.command(name="admin_message", description="Send a server message as Admin (Owner).")
@log_exceptions("admin_message_command")
async def admin_message_command(interaction: discord.Interaction, message: str):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "admin_message"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_bot_message, "Admin", message)
    if not mc_result:
        await interaction.followup.send(f"✅ Sent: [Admin] {message}", ephemeral=True)
    elif "RCON Error" in (mc_result or ""):
        await interaction.followup.send(f"❌ Failed to send message: {mc_result}", ephemeral=True)
    else:
        await interaction.followup.send(f"✅ Sent: [Admin] {message}\n(Server said: {mc_result})", ephemeral=True)


@app_commands.command(name="bot_command", description="Run a raw server command (Owner generic).")
@log_exceptions("bot_command")
async def bot_command(interaction: discord.Interaction, command: str):
    await interaction.response.defer(ephemeral=True)
    # Gate by generic owner flag
    if not PERMS.can(interaction.user.id, "owner"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon._send_rcon_command, command)
    if not mc_result:
        await interaction.followup.send("✅ Command executed. (no output)", ephemeral=True)
    elif "RCON Error" in (mc_result or ""):
        await interaction.followup.send(f"❌ Failed: {mc_result}", ephemeral=True)
    else:
        await interaction.followup.send(f"✅ Command executed.\n```\n{mc_result}\n```", ephemeral=True)


@app_commands.command(name="bedrock_whitelist", description="Whitelist a Bedrock player (fwhitelist add).")
@log_exceptions("bedrock_whitelist")
async def bedrock_whitelist_command(interaction: discord.Interaction, username: str):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "whitelist"):
        await interaction.followup.send(_no_perm_msg(interaction.user, username), ephemeral=False)
        return

    cmd = f"fwhitelist add {username}"
    result = await asyncio.to_thread(mc_rcon._send_rcon_command, cmd)

    if looks_like_not_found(result):
        await interaction.followup.send(
            "❌ No such player found. The player should attempt to connect once, then try whitelisting again.",
            ephemeral=False,
        )
        return

    await interaction.followup.send(f"✅ Bedrock whitelist attempted for `{username}`.\n(Server said: `{result}`)", ephemeral=False)


@app_commands.command(name="bedrock_unwhitelist", description="Unwhitelist a Bedrock player (fwhitelist remove).")
@log_exceptions("bedrock_unwhitelist")
async def bedrock_unwhitelist_command(interaction: discord.Interaction, username: str):
    await interaction.response.defer(ephemeral=False)
    if not PERMS.can(interaction.user.id, "unwhitelist"):
        await interaction.followup.send(_no_perm_msg(interaction.user, username), ephemeral=False)
        return

    cmd = f"fwhitelist remove {username}"
    result = await asyncio.to_thread(mc_rcon._send_rcon_command, cmd)

    if looks_like_not_found(result):
        await interaction.followup.send(
            "❌ No such player found. The player should attempt to connect once, then try again.",
            ephemeral=False,
        )
        return

    await interaction.followup.send(f"✅ Bedrock unwhitelist attempted for `{username}`.\n(Server said: `{result}`)", ephemeral=False)


@app_commands.command(name="register_my_ign", description="Register your Minecraft IGN (must match usercache.json exactly).")
@log_exceptions("register_my_ign")
async def register_my_ign_command(interaction: discord.Interaction, ign: str):
    await interaction.response.defer(ephemeral=True)

    existing = PERMS.get_registered_igns(interaction.user.id)
    if existing:
        await interaction.followup.send(f"❌ You are already registered as: {', '.join(existing)}", ephemeral=True)
        return

    uuid = PERMS.lookup_usercache_exact(ign)
    if not uuid:
        await interaction.followup.send(
            "❌ No such player found in usercache.json (case-sensitive).\n"
            "They should attempt to connect once, then try again.",
            ephemeral=True,
        )
        return

    other = PERMS.ign_in_use_by_other(ign, interaction.user.id)
    if other:
        await interaction.followup.send("❌ That IGN is already registered to another Discord account.", ephemeral=True)
        return

    PERMS.set_user_igns(interaction.user.id, [ign], [uuid])
    await interaction.followup.send(f"✅ Registered you as `{ign}`.", ephemeral=True)


@app_commands.command(name="unregister_my_ign", description="Remove your registered Minecraft IGN(s).")
@log_exceptions("unregister_my_ign")
async def unregister_my_ign_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    existing = PERMS.get_registered_igns(interaction.user.id)
    if not existing:
        await interaction.followup.send("ℹ️ You have no registered IGN.", ephemeral=True)
        return

    PERMS.set_user_igns(interaction.user.id, [], [])
    await interaction.followup.send("✅ Your IGN registration has been cleared.", ephemeral=True)


@app_commands.command(name="register_player_ign", description="Owner-only: register an IGN for a Discord user (adds additional IGNs).")
@log_exceptions("register_player_ign")
async def register_player_ign_command(interaction: discord.Interaction, member: discord.Member, ign: str):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "set_role"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    uuid = PERMS.lookup_usercache_exact(ign)
    if not uuid:
        await interaction.followup.send(
            "❌ No such player found in usercache.json (case-sensitive).\n"
            "They should attempt to connect once, then try again.",
            ephemeral=True,
        )
        return

    other = PERMS.ign_in_use_by_other(ign, member.id)
    if other:
        await interaction.followup.send("❌ That IGN is already registered to another Discord account.", ephemeral=True)
        return

    PERMS.append_user_ign(member.id, ign, uuid)
    await interaction.followup.send(f"✅ Added `{ign}` to {member.display_name}.", ephemeral=True)


@app_commands.command(name="unregister_player_ign", description="Owner-only: clear all registered IGNs for a Discord user.")
@log_exceptions("unregister_player_ign")
async def unregister_player_ign_command(interaction: discord.Interaction, member: discord.Member):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "set_role"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    PERMS.set_user_igns(member.id, [], [])
    await interaction.followup.send(f"✅ Cleared IGN(s) for {member.display_name}.", ephemeral=True)


@app_commands.command(name="set_role", description="Owner-only: set a Discord user's role (Guest/Member/Mod/Owner).")
@log_exceptions("set_role")
async def set_role_command(interaction: discord.Interaction, member: discord.Member, role: str):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "set_role"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return
    try:
        PERMS.set_role(member.id, role)
        await interaction.followup.send(f"✅ Set role for {member.display_name} → `{role}`.", ephemeral=True)
    except ValueError as e:
        await interaction.followup.send(f"❌ {e}", ephemeral=True)


@app_commands.command(name="set_permission", description="Owner-only: set a permission boolean for a Discord user.")
@log_exceptions("set_permission")
async def set_permission_command(interaction: discord.Interaction, member: discord.Member, permission: str, value: bool):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "set_permission"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return
    try:
        PERMS.set_permission(member.id, permission, value)
        await interaction.followup.send(f"✅ Set {member.display_name}.{permission} = {value}", ephemeral=True)
    except ValueError as e:
        await interaction.followup.send(f"❌ {e}", ephemeral=True)


@app_commands.command(name="set_blocker", description="Owner-only: set a blocker on a player (bannable/kickable/unwhitelistable).")
@log_exceptions("set_blocker")
async def set_blocker_command(interaction: discord.Interaction, player: str, blocker: str, value: bool):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "set_blockers"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    # allow passing a discord user string; apply to all their registered IGNs
    member = _find_member_by_string(interaction.guild, player) if interaction.guild else None
    if member:
        igns = PERMS.get_registered_igns(member.id)
        if not igns:
            await interaction.followup.send("❌ That Discord user has no registered IGN(s).", ephemeral=True)
            return
        for ign in igns:
            PERMS.set_blocker(ign, blocker, value)
        await interaction.followup.send(f"✅ Set blocker `{blocker}`={value} for {member.display_name} ({', '.join(igns)}).", ephemeral=True)
        return

    try:
        PERMS.set_blocker(player, blocker, value)
        await interaction.followup.send(f"✅ Set blocker `{blocker}`={value} for `{player}`.", ephemeral=True)
    except ValueError as e:
        await interaction.followup.send(f"❌ {e}", ephemeral=True)


@app_commands.command(name="reload_perms", description="Owner-only: reload perms JSON and ensure all members exist as Guest.")
@log_exceptions("reload_perms")
async def reload_perms_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "reload_perms"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return

    PERMS.load()
    if interaction.guild:
        changed = await PERMS.ensure_all_members_have_records(interaction.guild)
        if changed:
            PERMS.save()

    await interaction.followup.send("✅ Permissions reloaded (and missing members added as Guest).", ephemeral=True)


@app_commands.command(name="verbose_true", description="Enable verbose logging (Owner).")
@log_exceptions("verbose_true_command")
async def verbose_true_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "owner"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return
    set_verbose_runtime(True, source=f"slash:{interaction.user.id}")
    await interaction.followup.send("✅ VERBOSE enabled.", ephemeral=True)

@app_commands.command(name="verbose_false", description="Disable verbose logging (Owner).")
@log_exceptions("verbose_false_command")
async def verbose_false_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if not PERMS.can(interaction.user.id, "owner"):
        await interaction.followup.send("❌ You don't have permission.", ephemeral=True)
        return
    set_verbose_runtime(False, source=f"slash:{interaction.user.id}")
    await interaction.followup.send("✅ VERBOSE disabled.", ephemeral=True)

# ---------------------------
# Presence updater (kept from your prior script)
# ---------------------------

def _rcon_port_open(host: str, port: int, timeout: float = 1.0, verbose: bool | None = None) -> bool:
    if verbose is None:
        verbose = VERBOSE
    try:
        with socket.create_connection((host, port), timeout=timeout):
            if verbose:
                vlog("_rcon_port_open(%s:%s) -> True", host, port)
            return True
    except OSError as e:
        if verbose:
            vlog("_rcon_port_open(%s:%s) -> False (%s)", host, port, e)
        return False

async def update_inquisitor_status(bot: commands.Bot):
    """Background presence updater."""
    log.info("presence: task starting; initial sleep=10s")
    failed_attempts = 0
    sleep_s = 10
    last_status_text = None

    await bot.wait_until_ready()
    while not bot.is_closed():
        loop_t0 = asyncio.get_running_loop().time()
        try:
            t0 = asyncio.get_running_loop().time()
            count, players = await asyncio.to_thread(mc_rcon.rcon_list)
            dt = asyncio.get_running_loop().time() - t0
            if VERBOSE:
                vlog("presence: rcon_list -> count=%s players=%s (%.3fs)",
                     count, players[:3] if players else [], dt)

            offline = False
            reason = "unknown"
            if count is None or count < 0 or players is None:
                offline = True
                reason = "bad_count_or_players"
            elif count == 0:
                try:
                    raw = await asyncio.to_thread(mc_rcon._send_rcon_command, "list")
                    raw_str = (raw or "").lower()
                    offline = (not raw_str) or ("rcon error" in raw_str) or ("timed out" in raw_str)
                    reason = f"raw_probe={raw_str[:60]!r}" if offline else "raw_probe_ok"
                except Exception as e:
                    offline = True
                    reason = f"raw_probe_exc={e!r}"
                if offline:
                    port_open = await asyncio.to_thread(
                        _rcon_port_open, rcon_config.HOST, rcon_config.PORT, 1.0, VERBOSE
                    )
                    if port_open:
                        offline = False
                        reason = "tcp_open_treat_empty"
            else:
                reason = "players_present"

            if offline:
                failed_attempts += 1
                sleep_s = min(60, 10 * (2 ** (failed_attempts - 1)))
                new_text = "server (offline)"
                if VERBOSE:
                    vlog("presence: OFFLINE (%s) failed_attempts=%s next_sleep=%ss",
                         reason, failed_attempts, sleep_s)
            else:
                failed_attempts = 0
                sleep_s = 10
                if count == 0:
                    new_text = "over 0 players"
                elif count == 1:
                    new_text = "over 1 player"
                else:
                    new_text = f"over {count} players"
                if VERBOSE:
                    vlog("presence: ONLINE (%s) new_text=%r next_sleep=%ss",
                         reason, new_text, sleep_s)

            if new_text != last_status_text:
                try:
                    activity = discord.Activity(type=discord.ActivityType.watching, name=new_text)
                    await bot.change_presence(activity=activity)
                    log.info("presence: updated → %r", new_text)
                    last_status_text = new_text
                except Exception:
                    log.exception("presence: failed to change presence to %r", new_text)
            else:
                if VERBOSE:
                    vlog("presence: unchanged (%r) — skipping update", new_text)

        except Exception:
            failed_attempts += 1
            sleep_s = min(60, 10 * (2 ** (failed_attempts - 1)))
            log.exception("presence: unexpected error; marking offline (sleep=%ss)", sleep_s)
            try:
                await bot.change_presence(activity=discord.Activity(
                    type=discord.ActivityType.watching, name="server (offline)"
                ))
                last_status_text = "server (offline)"
            except Exception:
                log.exception("presence: failed to set offline presence")

        loop_dt = asyncio.get_running_loop().time() - loop_t0
        if VERBOSE:
            vlog("presence: loop time %.3fs; sleeping %ss", loop_dt, sleep_s)
        await asyncio.sleep(sleep_s)

# ---------------------------
# Command registry helpers
# ---------------------------

def _cmdsig(cmd: app_commands.AppCommand) -> str:
    scope = "GLOBAL" if cmd.guild_ids is None else f"GUILDS={cmd.guild_ids}"
    return f"{cmd.name} ({scope}) id={getattr(cmd, 'id', '?')}"

async def _dump_tree(tree: app_commands.CommandTree, guild_id: int | None = None):
    try:
        if guild_id:
            cmds = await tree.fetch_commands(guild=discord.Object(id=guild_id))
            log.info("Command registry (GUILD %s): %s", guild_id, ", ".join(sorted(c.name for c in cmds)) or "<none>")
            for c in cmds:
                if VERBOSE: vlog("  • %s", _cmdsig(c))
        else:
            cmds = await tree.fetch_commands()
            log.info("Command registry (GLOBAL): %s", ", ".join(sorted(c.name for c in cmds)) or "<none>")
            for c in cmds:
                if VERBOSE: vlog("  • %s", _cmdsig(c))
    except Exception:
        log.exception("Failed to dump command registry (guild=%s)", guild_id)

def _maybe_add(tree: app_commands.CommandTree, name: str, guild: discord.Object):
    fn = globals().get(name)
    if fn is None:
        log.error("sync: skipping %s (not defined at import time)", name)
        return
    if not isinstance(fn, app_commands.Command):
        log.error("sync: %s is %s, not an AppCommand", name, type(fn).__name__)
        return
    tree.add_command(fn, guild=guild)

# ---------------------------
# on_ready: bootstrap perms + sync commands
# ---------------------------

@bot.event
async def on_ready():
    log.info("on_ready: Logged in as %s (%s)", bot.user, getattr(bot.user, "id", "?"))

    if getattr(bot, "_inq_ready_once", False):
        log.info("on_ready: already initialized once; skipping re-init")
        return
    bot._inq_ready_once = True

    # Ensure every member has a record (default Guest) on startup
    try:
        g = bot.get_guild(GUILD_ID)
        if g:
            changed = await PERMS.ensure_all_members_have_records(g)
            if changed:
                PERMS.save()
                log.info("perms: added missing members as Guest (startup)")
        else:
            log.warning("perms: guild not cached; skipping startup ensure_all_members")
    except Exception:
        log.exception("perms: failed ensuring all members have records")

    await update_inquisitor_intro(bot)

    # Start/ensure presence task; restart if it ever ends
    async def _start_presence():
        bot._inq_status_task = asyncio.create_task(update_inquisitor_status(bot), name="inq_presence")
        log.info("presence: started background task (id=%s)", id(bot._inq_status_task))
        def _presence_task_done(t: asyncio.Task):
            try:
                t.result()
                log.warning("presence: task finished unexpectedly; restarting")
            except asyncio.CancelledError:
                log.warning("presence: task was cancelled; restarting")
            except Exception:
                log.exception("presence: task crashed; restarting")
            asyncio.get_running_loop().call_later(2.0, lambda: asyncio.create_task(_start_presence()))
        bot._inq_status_task.add_done_callback(_presence_task_done)

    await _start_presence()

    # --- Clean publish sequence (guild-only) ---
    try:
        guild = discord.Object(id=GUILD_ID)

        tree.clear_commands(guild=guild)
        tree.clear_commands(guild=None)

        for n in [
            "verbose_true_command", "verbose_false_command",
            "weather_clear_command",
            "whitelist_command", "unwhitelist_command", "kick_command", "ban_command", "unban_command",
            "bedrock_whitelist_command", "bedrock_unwhitelist_command",
            "bot_message_command", "admin_message_command", "bot_command",
            "register_my_ign_command", "unregister_my_ign_command",
            "register_player_ign_command", "unregister_player_ign_command",
            "set_role_command", "set_permission_command", "set_blocker_command",
            "reload_perms_command",
        ]:
            _maybe_add(tree, n, guild)

        guild_synced = await tree.sync(guild=guild)
        log.info("✅ Synced %d guild slash commands", len(guild_synced))
        print(f"✅ Synced {len(guild_synced)} guild slash commands")

        await tree.sync(guild=None)
        log.info("🌍 Cleared global slash commands (using empty sync)")

        await _dump_tree(tree, guild_id=GUILD_ID)
        await _dump_tree(tree, guild_id=None)

    except Exception as e:
        log.exception("❌ Failed to sync slash commands: %s", e)
        print(f"❌ Failed to sync slash commands: {e}")

if __name__ == "__main__":
    log.info("Starting Discord gateway...")
    print("[BOOT] calling bot.run()", flush=True)
    bot.run(INQUISITOR_TOKEN)
