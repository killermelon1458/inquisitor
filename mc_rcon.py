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
    """Single, safe, synchronous call with timeout + one reconnect attempt."""
    global RCON_CLIENT
    with _RCON_LOCK:
        if RCON_CLIENT is None:
            _connect()
            if RCON_CLIENT is None:
                return _safe_error("Not connected.")

        try:
            return RCON_CLIENT.command(cmd)
        except (socket.timeout, TimeoutError) as e:
            # reconnect once on timeout
            try:
                RCON_CLIENT.disconnect()
            except Exception:
                pass
            RCON_CLIENT = None
            _connect()
            if RCON_CLIENT is None:
                return _safe_error("Timed out (reconnect failed).")
            try:
                return RCON_CLIENT.command(cmd)
            except Exception as e2:
                return _safe_error(f"{type(e2).__name__}: {e2}")
        except (OSError, ConnectionError) as e:
            # hard drop → reconnect next time
            try:
                RCON_CLIENT.disconnect()
            except Exception:
                pass
            RCON_CLIENT = None
            return _safe_error(f"{type(e).__name__}: {e}")
        except Exception as e:
            return _safe_error(f"{type(e).__name__}: {e}")

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
