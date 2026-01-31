# mc_rcon.py — make calls fast-fail + thread-safe
import socket, threading
from mcrcon import MCRcon

_RCON_LOCK = threading.Lock()
_CFG = {"host": None, "port": None, "password": None, "timeout": 2.5}
RCON_CLIENT: MCRcon | None = None

def set_rcon_config(host: str, port: int, password: str, timeout: float = 2.5):
    global _CFG, RCON_CLIENT
    _CFG.update({"host": host, "port": port, "password": password, "timeout": timeout})
    with _RCON_LOCK:
        if RCON_CLIENT:
            try:
                RCON_CLIENT.disconnect()
            except Exception:
                pass
            RCON_CLIENT = None
    _connect()

def _connect():
    """(Re)connect the client; socket has a timeout so recv can't hang forever."""
    global RCON_CLIENT
    try:
        c = MCRcon(_CFG["host"], _CFG["password"], port=_CFG["port"])
        c.connect()
        try:
            # mcrcon exposes the underlying socket as .socket
            c.socket.settimeout(_CFG["timeout"])
        except Exception:
            pass
        RCON_CLIENT = c
    except Exception:
        RCON_CLIENT = None  # will be handled by caller

def _safe_error(msg: str) -> str:
    return f"[RCON Error] {msg}"

def _send_rcon_command(cmd: str) -> str:
    """
    Safe RCON call.
    Rule: ANY failure poisons the client → drop it → reconnect once → retry once.
    No stale sockets are ever reused.
    """
    global RCON_CLIENT

    with _RCON_LOCK:
        # Ensure we have a client
        if RCON_CLIENT is None:
            _connect()
            if RCON_CLIENT is None:
                return _safe_error("Not connected.")

        try:
            # First attempt
            return RCON_CLIENT.command(cmd)

        except Exception as e:
            # ANY exception = client is invalid
            try:
                RCON_CLIENT.disconnect()
            except Exception:
                pass

            RCON_CLIENT = None

            # One clean reconnect attempt
            _connect()
            if RCON_CLIENT is None:
                return _safe_error(f"Reconnect failed: {type(e).__name__}: {e}")

            try:
                return RCON_CLIENT.command(cmd)
            except Exception as e2:
                # Second failure → give up, leave client cleared
                try:
                    RCON_CLIENT.disconnect()
                except Exception:
                    pass
                RCON_CLIENT = None
                return _safe_error(f"{type(e2).__name__}: {e2}")

# convenience wrappers (unchanged signatures)
def rcon_list():
    res = _send_rcon_command("list")
    if not res or "RCON Error" in res:
        return 0, []
    # Paper/Vanilla typical: "There are X of a max of Y players online: a, b, c"
    parts = res.split(":", 1)
    count = 0
    try:
        import re
        m = re.search(r"There are\s+(\d+)", res)
        if m: count = int(m.group(1))
    except Exception:
        pass
    players = []
    if len(parts) == 2 and parts[1].strip():
        players = [p.strip() for p in parts[1].split(",") if p.strip()]
    return count, players

def rcon_whitelist(player: str): return _send_rcon_command(f"whitelist add {player}")
def rcon_unwhitelist(player: str): return _send_rcon_command(f"whitelist remove {player}")
def rcon_kick(player: str, reason: str = ""): return _send_rcon_command(f'kick {player} {reason}'.strip())
def rcon_ban(player: str, reason: str = ""): return _send_rcon_command(f'ban {player} {reason}'.strip())
def rcon_weather_clear(): return _send_rcon_command("weather clear")
def rcon_bot_message(tag: str, message: str):
    # tellraw returns empty string on success; keep behavior
    return _send_rcon_command(
        f'''tellraw @a ["",{{"text":"[{tag}] ","color":"gold"}},{{"text":"{message}","color":"white"}}]'''
    )
