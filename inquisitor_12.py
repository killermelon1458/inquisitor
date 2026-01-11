# ==== Logging & Verbose bootstrap (must be first) ====
from __future__ import annotations
import os, sys, argparse, time, faulthandler, threading, contextlib, traceback, functools
from logging.handlers import RotatingFileHandler
import logging

# Parse VERBOSE from argv/env (both supported)
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--verbose", action="store_true")
# also accept VERBOSE=1 style
_env_verbose = os.environ.get("VERBOSE", "").strip()
_argv_verbose = any(a.strip().lower() in ("--verbose", "verbose", "verbose=1", "verbose=true") for a in sys.argv[1:])
_args, _unknown = _parser.parse_known_args()
VERBOSE: bool = bool(_args.verbose or _argv_verbose or _env_verbose in ("1","true","True"))

# ==== Verbose utilities ====
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


# Create logs dir
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR  = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Configure root logger
_log_level = logging.DEBUG if VERBOSE else logging.INFO   # init steps log at INFO; extra chatter at DEBUG when verbose
_handlers = [
    RotatingFileHandler(os.path.join(LOG_DIR, "inquisitor.log"), maxBytes=2_000_000, backupCount=5, encoding="utf-8"),
    logging.StreamHandler(sys.stdout),
]
logging.basicConfig(level=_log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=_handlers)
log = logging.getLogger("inquisitor")

# Make third-party libraries chatty only when verbose
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
        # dump to stderr (captured by console and BAT tee), also mirror into log
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


import discord
from discord.ext import commands
from discord import app_commands
import mc_rcon
import rcon_config
from message_manager import get_message
from inquisitor_token import INQUISITOR_TOKEN, GUILD_ID, PREFIX
import asyncio


INQUISITOR_CHANNEL_ID=1423093468405825616

# --- Init RCON ---
with hang_watch("RCON set_rcon_config (connect-on-init?)", seconds=15):
    log.info("RCON: applying config host=%s port=%s (short timeout expected to avoid hangs)", getattr(rcon_config, "HOST", "?"), getattr(rcon_config, "PORT", "?"))
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


# --- Permissions ---
def load_permissions(filepath: str, verbose: bool | None = None) -> list[str]:
    if verbose is None: verbose = VERBOSE
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            ids = []
            for line in f:
                clean = line.split("#", 1)[0].strip()
                if clean:
                    ids.append(clean)
            if verbose:
                vlog("load_permissions(%s) -> %d id(s)", filepath, len(ids))
            return ids
    except FileNotFoundError:
        log.warning("[Warning] Permission file not found: %s", filepath)
        return []

async def check_permission(discord_user, player: str, perm_file: str, verbose: bool | None = None) -> str | None:
    if verbose is None: verbose = VERBOSE
    allowed_ids = load_permissions(perm_file, verbose=verbose)
    allowed = (str(discord_user.id) in allowed_ids)
    if verbose:
        vlog("check_permission(user=%s id=%s, file=%s) -> %s",
             discord_user.name, discord_user.id, perm_file, allowed)
    if not allowed:
        msg = get_message("no_permission", "inquisitor_no_permission_messages.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")
    return None
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

    # --- Server offline errors ---
    if "rcon error" in result_lower:
        offline_keywords = ["getaddrinfo", "refused", "offline", "timed out", "10060", "failed to respond"]
        if any(keyword in result_lower for keyword in offline_keywords):
            msg = get_message("server_offline", "inquisitor_server_not_online.txt")
        else:
            msg = get_message("action_failed", "inquisitor_action_failed.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    # --- Explicit game failure responses ---
    fail_keywords = ["does not exist", "unknown player", "already whitelisted", "not whitelisted", "cannot ban", "cannot kick"]
    if any(keyword in result_lower for keyword in fail_keywords):
        msg = get_message("failed_action", "inquisitor_action_failed.txt")
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    # --- Explicit success responses ---
    success_keywords = ["added", "removed", "kicked", "banned", "changed", "set the weather", "cleared"]
    if any(keyword in result_lower for keyword in success_keywords):
        msg = get_message("success", success_file)
        return msg.format(discord_user=discord_user.name, player=player or "N/A")

    # --- Fallback: treat anything unknown as failure ---
    msg = get_message("failed_action", "inquisitor_action_failed.txt")
    return msg.format(discord_user=discord_user.name, player=player or "N/A")

def load_protected(filepath: str, verbose: bool | None = None) -> list[str]:
    if verbose is None:
        verbose = VERBOSE
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            names = []
            for line in f:
                clean = line.split("#", 1)[0].strip()
                if clean:
                    names.append(clean.lower())  # store lowercase for matching
            if verbose:
                vlog("load_protected(%s) -> %d names", filepath, len(names))
            return names
    except FileNotFoundError:
        print(f"[Warning] Protected file not found: {filepath}")
        log.warning("[Warning] Protected file not found: %s", filepath)
        return []

@log_exceptions("update_inquisitor_intro")
async def update_inquisitor_intro(bot, verbose: bool | None = None):
    if verbose is None: verbose = VERBOSE
    channel = bot.get_channel(INQUISITOR_CHANNEL_ID)
    if not channel:
        log.warning("update_inquisitor_intro: channel %s not found", INQUISITOR_CHANNEL_ID)
        return
    if verbose:
        vlog("update_inquisitor_intro: scanning channel history for existing intro message")

    intro_message = (
        "I am the Inquisitor. I judge, I permit, I deny. My will is law.\n\n"
        "`/whitelist <player>` — I permit their entry, but only because you command it.\n"
        "`/unwhitelist <player>` — Their passage is revoked. They no longer belong.\n"
        "`/kick <player>` — Cast out, for now. Let them reflect on their place.\n"
        "`/ban <player>` — Their name is erased from the record. They shall not return.\n"
        "`/clear_weather` — Tch… fine. The skies will obey me, this once.\n\n"
        "⚖️ Remember: I do not obey all who call. Only those with authority may command me."
    )

    async for msg in channel.history(limit=50):
        if msg.author == bot.user and not msg.embeds:
            await msg.edit(content=intro_message)
            if verbose: vlog("update_inquisitor_intro: edited existing message %s", msg.id)
            return

    await channel.send(intro_message)
    if verbose: vlog("update_inquisitor_intro: sent new intro message")
    

@app_commands.command(name="whitelist", description="Whitelist a player.")
@log_exceptions("whitelist_command")
async def whitelist_command(interaction: discord.Interaction, player: str):
    if VERBOSE: vlog("whitelist invoked by %s for %s", interaction.user.id, player)
    await interaction.response.defer(ephemeral=False)
    no_perm = await check_permission(interaction.user, player, "mod_perms.txt")
    if no_perm:
        await interaction.followup.send(no_perm, ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_whitelist, player)
    print(f"[RCON][whitelist] user={interaction.user} player={player} result={mc_result}")
    if VERBOSE: vlog("whitelist rcon result: %r", mc_result)
    formatted = choose_message(mc_result, "inquisitor_whitelist_messages.txt", interaction.user, player)
    #await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", formatted)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)

    await interaction.followup.send(formatted, ephemeral=False)


@app_commands.command(name="unwhitelist", description="Remove a player from whitelist.")
@log_exceptions("unwhitelist_command")
async def unwhitelist_command(interaction: discord.Interaction, player: str):
    if VERBOSE: vlog("unwhitelist invoked by %s (%s) for player=%r", interaction.user.name, interaction.user.id, player)
    await interaction.response.defer(ephemeral=False)

    no_perm = await check_permission(interaction.user, player, "mod_perms.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("unwhitelist: no permission")
        await interaction.followup.send(no_perm, ephemeral=False)
        return

    # --- Protected check ---
    protected = load_protected("unbannable.txt", verbose=VERBOSE) + load_protected("unkickable.txt", verbose=VERBOSE)
    if player.lower() in protected:
        msg = get_message("protected", "inquisitor_protected_player.txt")
        formatted = msg.format(discord_user=interaction.user.name, player=player)
        log.info("unwhitelist: blocked protected player=%s by %s", player, interaction.user.name)
        await interaction.followup.send(formatted, ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_unwhitelist, player)
    if VERBOSE: vlog("unwhitelist rcon result: %r", mc_result)
    formatted = choose_message(mc_result, "inquisitor_unwhitelist_messages.txt", interaction.user, player, verbose=VERBOSE)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)

    #await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", formatted)
    log.info("unwhitelist: %s -> %s", player, "OK" if not mc_result or not mc_result.lower().startswith("rcon error") else "ERR")
    await interaction.followup.send(formatted, ephemeral=False)



@app_commands.command(name="kick", description="Kick a player.")
@log_exceptions("kick_command")
async def kick_command(interaction: discord.Interaction, player: str, reason: str = ""):
    if VERBOSE: vlog("kick invoked by %s (%s) for player=%r reason=%r", interaction.user.name, interaction.user.id, player, reason)
    await interaction.response.defer(ephemeral=False)

    no_perm = await check_permission(interaction.user, player, "all_members.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("kick: no permission")
        await interaction.followup.send(no_perm, ephemeral=False)
        return

    unkickable = load_protected("unkickable.txt", verbose=VERBOSE)
    if player.lower() in unkickable:
        msg = get_message("protected", "inquisitor_protected_player.txt")
        formatted = msg.format(discord_user=interaction.user.name, player=player)
        log.info("kick: blocked unkickable player=%s by %s", player, interaction.user.name)
        await interaction.followup.send(formatted, ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_kick, player, reason)
    if VERBOSE: vlog("kick rcon result: %r", mc_result)
    formatted = choose_message(mc_result, "inquisitor_kick_messages.txt", interaction.user, player, verbose=VERBOSE)

    #await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", formatted)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)

    log.info("kick: %s reason=%r -> %s", player, reason, "OK" if not mc_result or not mc_result.lower().startswith("rcon error") else "ERR")
    await interaction.followup.send(formatted, ephemeral=False)



@app_commands.command(name="ban", description="Ban a player.")
@log_exceptions("ban_command")
async def ban_command(interaction: discord.Interaction, player: str, reason: str = ""):
    if VERBOSE: vlog("ban invoked by %s (%s) for player=%r reason=%r", interaction.user.name, interaction.user.id, player, reason)
    await interaction.response.defer(ephemeral=False)

    no_perm = await check_permission(interaction.user, player, "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("ban: no permission")
        await interaction.followup.send(no_perm, ephemeral=False)
        return

    unbannable = load_protected("unbannable.txt", verbose=VERBOSE)
    if player.lower() in unbannable:
        msg = get_message("protected", "inquisitor_protected_player.txt")
        formatted = msg.format(discord_user=interaction.user.name, player=player)
        log.info("ban: blocked unbannable player=%s by %s", player, interaction.user.name)
        await interaction.followup.send(formatted, ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_ban, player, reason)
    if VERBOSE: vlog("ban rcon result: %r", mc_result)
    formatted = choose_message(mc_result, "inquisitor_ban_messages.txt", interaction.user, player, verbose=VERBOSE)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)

    #await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", formatted)
    log.info("ban: %s reason=%r -> %s", player, reason, "OK" if not mc_result or not mc_result.lower().startswith("rcon error") else "ERR")
    await interaction.followup.send(formatted, ephemeral=False)



@app_commands.command(name="clear_weather", description="Clear the server weather.")
@log_exceptions("clear_weather_command")
async def clear_weather_command(interaction: discord.Interaction):
    if VERBOSE: vlog("clear_weather invoked by %s (%s)", interaction.user.name, interaction.user.id)
    await interaction.response.defer(ephemeral=False)

    no_perm = await check_permission(interaction.user, "", "all_members.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("clear_weather: no permission")
        await interaction.followup.send(no_perm, ephemeral=False)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_weather_clear)
    if VERBOSE: vlog("clear_weather rcon result: %r", mc_result)
    formatted = choose_message(mc_result, "inquisitor_weather_messages.txt", interaction.user, "N/A", verbose=VERBOSE)
    await _send_ingame_maybe(interaction.channel_id, "Inquisitor", formatted)

    #await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", formatted)
    log.info("clear_weather: -> %s", "OK" if not mc_result or not mc_result.lower().startswith("rcon error") else "ERR")
    await interaction.followup.send(formatted, ephemeral=False)



@app_commands.command(name="bot_message", description="Send a server message as Inquisitor.")
@log_exceptions("bot_message_command")
async def bot_message_command(interaction: discord.Interaction, message: str):
    if VERBOSE: vlog("bot_message invoked by %s (%s) message=%r", interaction.user.name, interaction.user.id, message)
    await interaction.response.defer(ephemeral=True)

    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("bot_message: no permission")
        await interaction.followup.send(no_perm, ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_bot_message, "Inquisitor", message)
    if VERBOSE: vlog("bot_message rcon result: %r", mc_result)

    if not mc_result:
        log.info("bot_message: tellraw OK")
        await interaction.followup.send(f"✅ Sent: [Inquisitor] {message}", ephemeral=True)
    elif "RCON Error" in mc_result:
        log.warning("bot_message: RCON error: %r", mc_result)
        await interaction.followup.send(f"❌ Failed to send message: {mc_result}", ephemeral=True)
    else:
        log.info("bot_message: tellraw OK (server echoed)")
        await interaction.followup.send(f"✅ Sent: [Inquisitor] {message}\n(Server said: {mc_result})", ephemeral=True)



@app_commands.command(name="bot_command", description="Run a raw server command (Owner only).")
@log_exceptions("bot_command")
async def bot_command(interaction: discord.Interaction, command: str):
    if VERBOSE: vlog("bot_command invoked by %s (%s) cmd=%r", interaction.user.name, interaction.user.id, command)
    await interaction.response.defer(ephemeral=True)

    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("bot_command: no permission")
        await interaction.followup.send(no_perm, ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon._send_rcon_command, command)
    if VERBOSE: vlog("bot_command rcon result: %r", mc_result)

    if not mc_result:
        log.info("bot_command: executed (no output)")
        await interaction.followup.send("✅ Command executed. (no output)", ephemeral=True)
    elif "RCON Error" in (mc_result or ""):
        log.warning("bot_command: RCON error: %r", mc_result)
        await interaction.followup.send(f"❌ Failed: {mc_result}", ephemeral=True)
    else:
        log.info("bot_command: executed with output (%d chars)", len(mc_result))
        await interaction.followup.send(f"✅ Command executed.\n```\n{mc_result}\n```", ephemeral=True)



@app_commands.command(name="admin_message", description="Send a server message as Admin.")
@log_exceptions("admin_message_command")
async def admin_message_command(interaction: discord.Interaction, message: str):
    if VERBOSE: vlog("admin_message invoked by %s (%s) message=%r", interaction.user.name, interaction.user.id, message)
    await interaction.response.defer(ephemeral=True)

    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        if VERBOSE: vlog("admin_message: no permission")
        await interaction.followup.send(no_perm, ephemeral=True)
        return

    mc_result = await asyncio.to_thread(mc_rcon.rcon_bot_message, "Admin", message)
    if VERBOSE: vlog("admin_message rcon result: %r", mc_result)

    if not mc_result:
        log.info("admin_message: tellraw OK")
        await interaction.followup.send(f"✅ Sent: [Admin] {message}", ephemeral=True)
    elif "RCON Error" in mc_result:
        log.warning("admin_message: RCON error: %r", mc_result)
        await interaction.followup.send(f"❌ Failed to send message: {mc_result}", ephemeral=True)
    else:
        log.info("admin_message: tellraw OK (server echoed)")
        await interaction.followup.send(f"✅ Sent: [Admin] {message}\n(Server said: {mc_result})", ephemeral=True)


@app_commands.command(name="verbose_true", description="Enable verbose logging (owner only).")
@log_exceptions("verbose_true_command")
async def verbose_true_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        await interaction.followup.send(no_perm, ephemeral=True)
        return
    set_verbose_runtime(True, source=f"slash:{interaction.user.id}")
    await interaction.followup.send("✅ VERBOSE enabled.", ephemeral=True)


@app_commands.command(name="verbose_false", description="Disable verbose logging (owner only).")
@log_exceptions("verbose_false_command")
async def verbose_false_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        await interaction.followup.send(no_perm, ephemeral=True)
        return
    set_verbose_runtime(False, source=f"slash:{interaction.user.id}")
    await interaction.followup.send("✅ VERBOSE disabled.", ephemeral=True)


# --- Events, Presence, and Robust Sync ---

import socket

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
                if last_status_text != "server (offline)":
                    log.info("presence: forced update → 'server (offline)'")
                last_status_text = "server (offline)"
            except Exception:
                log.exception("presence: failed to set offline presence")

        loop_dt = asyncio.get_running_loop().time() - loop_t0
        if VERBOSE:
            vlog("presence: loop time %.3fs; sleeping %ss", loop_dt, sleep_s)
        await asyncio.sleep(sleep_s)


# Debug helpers for command registry
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
            cmds = await tree.fetch_commands()  # globals
            log.info("Command registry (GLOBAL): %s", ", ".join(sorted(c.name for c in cmds)) or "<none>")
            for c in cmds:
                if VERBOSE: vlog("  • %s", _cmdsig(c))
    except Exception:
        log.exception("Failed to dump command registry (guild=%s)", guild_id)

# Safe add helper that won’t crash if a command isn’t defined yet
def _maybe_add(tree: app_commands.CommandTree, name: str, guild: discord.Object):
    fn = globals().get(name)
    if fn is None:
        log.error("sync: skipping %s (not defined at import time)", name)
        return
    if not isinstance(fn, app_commands.Command):
        log.error("sync: %s is %s, not an AppCommand", name, type(fn).__name__)
        return
    tree.add_command(fn, guild=guild)


# Owner-only resync command
@app_commands.command(name="resync_commands", description="Owner-only: clear and resync slash commands.")
@log_exceptions("resync_commands_command")
async def resync_commands(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    no_perm = await check_permission(interaction.user, "", "owner_perms.txt", verbose=VERBOSE)
    if no_perm:
        await interaction.followup.send(no_perm, ephemeral=True)
        return
    try:
        guild = discord.Object(id=GUILD_ID)
        log.info("Resync: clearing guild and global commands…")
        tree.clear_commands(guild=guild)        # clear guild in local tree
        tree.clear_commands(guild=None)         # clear globals in local tree (keyword!)

        # re-add all as guild commands
        for n in [
            "verbose_true_command", "verbose_false_command",
            "whitelist_command", "unwhitelist_command", "kick_command", "ban_command",
            "clear_weather_command", "bot_message_command", "bot_command", "admin_message_command",
            "resync_commands",
        ]:
            _maybe_add(tree, n, guild)

        guild_synced = await tree.sync(guild=guild)
        log.info("✅ Resync: published %d guild commands", len(guild_synced))

        await tree.sync(guild=None)             # empty global set → clears remote globals
        log.info("🌍 Resync: cleared global commands")

        await _dump_tree(tree, guild_id=GUILD_ID)
        await _dump_tree(tree, guild_id=None)

        await interaction.followup.send("✅ Commands resynced (guild-only) and globals cleared.", ephemeral=True)
    except Exception as e:
        log.exception("Resync failed: %s", e)
        await interaction.followup.send(f"❌ Resync failed: {e}", ephemeral=True)


# Single-shot on_ready with presence task auto-restart
@bot.event
async def on_ready():
    log.info("on_ready: Logged in as %s (%s)", bot.user, getattr(bot.user, "id", "?"))

    # only run this body once per process
    if getattr(bot, "_inq_ready_once", False):
        log.info("on_ready: already initialized once; skipping re-init")
        return
    bot._inq_ready_once = True

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
            # restart after a short delay to avoid hot-looping
            asyncio.get_running_loop().call_later(2.0, lambda: asyncio.create_task(_start_presence()))
        bot._inq_status_task.add_done_callback(_presence_task_done)

    await _start_presence()

    # --- Clean publish sequence (guild-only) ---
    try:
        guild = discord.Object(id=GUILD_ID)

        # clear local trees, then re-add fresh (use explicit keyword 'guild=')
        tree.clear_commands(guild=guild)        # local guild
        tree.clear_commands(guild=None)         # local globals

        # register everything as guild commands
        for n in [
            "verbose_true_command", "verbose_false_command",
            "whitelist_command", "unwhitelist_command", "kick_command", "ban_command",
            "clear_weather_command", "bot_message_command", "bot_command", "admin_message_command",
            "resync_commands",
        ]:
            _maybe_add(tree, n, guild)

        # publish guild (fast)
        guild_synced = await tree.sync(guild=guild)
        log.info("✅ Synced %d guild slash commands", len(guild_synced))
        print(f"✅ Synced {len(guild_synced)} guild slash commands")

        # ensure global commands are cleared remotely
        await tree.sync(guild=None)
        log.info("🌍 Cleared global slash commands (using empty sync)")

        # show what Discord thinks is live
        await _dump_tree(tree, guild_id=GUILD_ID)
        await _dump_tree(tree, guild_id=None)

    except Exception as e:
        log.exception("❌ Failed to sync slash commands: %s", e)
        print(f"❌ Failed to sync slash commands: {e}")

if __name__ == "__main__":
    log.info("Starting Discord gateway...")
    print("[BOOT] calling bot.run()", flush=True)
    bot.run(INQUISITOR_TOKEN)


# Usage examples:
#   python inquisitor_9.py                   -> normal logging (init INFO + errors)
#   VERBOSE=1 python inquisitor_9.py         -> verbose via env
#   python inquisitor_9.py --verbose         -> verbose via arg
