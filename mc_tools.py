# mc_rcon_beta.py — persistent RCON + optional dedicated connection logging (no behavior changes)
import os
import sys
import time
import socket
import threading
import logging
from pathlib import Path
from datetime import datetime
from itertools import count

try:
    # mcrcon uses signal-based timeouts during connect(), which breaks inside worker threads:
    #   ValueError: signal only works in main thread of the main interpreter
    # mctools uses socket timeouts and is safe to connect/reconnect from threads.
    from mctools import RCONClient
except Exception as _e:
    raise ImportError(
        "mctools is required for thread-safe RCON reconnects. "
        "Install in your venv: python -m pip install mctools"
    ) from _e

# ----------------------------
# RCON core state
# ----------------------------
_RCON_LOCK = threading.Lock()
_CFG = {"host": None, "port": None, "password": None, "timeout": 2.5}
RCON_CLIENT: RCONClient | None = None


# ----------------------------
# Dedicated RCON connection logging (separate file)
# ----------------------------
_RCON_CONN_LOG_ENABLED = False
_RCON_CONN_LOGGER: logging.Logger | None = None
_RCON_CONN_LOG_PATH: Path | None = None
_RCON_RUN_ID = f"pid={os.getpid()}_start={int(time.time())}"
_RCON_ATTEMPT_ID = count(1)

# Optional compatibility shim for inquisitor
def set_rcon_verbose(enabled: bool) -> None:
    """
    Thread-safe client does not gate logging on a verbose flag,
    but inquisitor expects this function to exist.
    """
    pass


def configure_rcon_connection_logging(
    enabled: bool,
    log_dir: str | os.PathLike | None = None,
    file_prefix: str = "rcon_connection",
) -> Path | None:
    """
    Enable/disable dedicated RCON connection logging to its own dated file.

    - If enabled=True: logs to {log_dir}/{file_prefix}_YYYY-MM-DD.log
    - If log_dir is None: defaults to ./logs next to this file
    - Returns the log path when enabled, else None.

    NOTE: This logger is intentionally isolated (does not touch root logger).
    """
    global _RCON_CONN_LOG_ENABLED, _RCON_CONN_LOGGER, _RCON_CONN_LOG_PATH

    _RCON_CONN_LOG_ENABLED = bool(enabled)

    # Tear down logger if disabling
    if not _RCON_CONN_LOG_ENABLED:
        if _RCON_CONN_LOGGER:
            for h in list(_RCON_CONN_LOGGER.handlers):
                try:
                    h.flush()
                    h.close()
                except Exception:
                    pass
                _RCON_CONN_LOGGER.removeHandler(h)
        _RCON_CONN_LOGGER = None
        _RCON_CONN_LOG_PATH = None
        return None

    # Resolve directory + file path
    if log_dir is None:
        base_dir = Path(__file__).resolve().parent
        log_dir_path = base_dir / "logs"
    else:
        log_dir_path = Path(log_dir).expanduser().resolve()

    log_dir_path.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d")
    log_path = log_dir_path / f"{file_prefix}_{date_str}.log"

    # Create/reconfigure isolated logger
    logger = logging.getLogger("mc_rcon.connection")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # never bubble into app/root logging

    # Clear existing handlers to avoid duplicates on reconfigure
    for h in list(logger.handlers):
        try:
            h.flush()
            h.close()
        except Exception:
            pass
        logger.removeHandler(h)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    _RCON_CONN_LOGGER = logger
    _RCON_CONN_LOG_PATH = log_path

    # Header dump (useful “what machine/context is this?” info)
    _rcon_log(
        "INFO",
        "RCON connection logging ENABLED",
        run_id=_RCON_RUN_ID,
        log_path=str(_RCON_CONN_LOG_PATH),
        python=sys.version.replace("\n", " "),
        platform=sys.platform,
        cwd=os.getcwd(),
        thread=threading.current_thread().name,
    )
    return _RCON_CONN_LOG_PATH


def get_rcon_connection_log_path() -> str | None:
    return str(_RCON_CONN_LOG_PATH) if _RCON_CONN_LOG_PATH else None


def _rcon_log(level: str, msg: str, **fields) -> None:
    """
    Lightweight structured logger.
    Never raises; never changes program behavior.
    """
    if not _RCON_CONN_LOG_ENABLED or _RCON_CONN_LOGGER is None:
        return
    try:
        # Flatten fields into key=value pairs (stable, grep-friendly)
        if fields:
            extras = " ".join(f"{k}={repr(v)}" for k, v in fields.items())
            line = f"{msg} | {extras}"
        else:
            line = msg

        lvl = level.upper()
        if lvl == "DEBUG":
            _RCON_CONN_LOGGER.debug(line)
        elif lvl == "INFO":
            _RCON_CONN_LOGGER.info(line)
        elif lvl == "WARNING":
            _RCON_CONN_LOGGER.warning(line)
        elif lvl == "ERROR":
            _RCON_CONN_LOGGER.error(line)
        else:
            _RCON_CONN_LOGGER.info(line)
    except Exception:
        # absolutely no side effects
        return


def _socket_snapshot(client: RCONClient | None) -> dict:
    """
    Best-effort introspection of the underlying socket.
    Works across different client implementations (mctools/mcrcon/etc).
    Returns dict of whatever we can safely extract.
    """
    snap: dict = {}

    if client is None:
        return snap

    sock = None
    # Common attribute names across libraries
    for attr in ("socket", "sock", "_sock", "_socket"):
        try:
            s = getattr(client, attr, None)
        except Exception:
            s = None
        if s is not None:
            sock = s
            break

    if sock is None:
        snap["socket_present"] = False
        return snap

    snap["socket_present"] = True
    try:
        snap["fileno"] = sock.fileno()
    except Exception:
        snap["fileno"] = None
    try:
        snap["sock_timeout"] = sock.gettimeout()
    except Exception:
        snap["sock_timeout"] = None
    try:
        snap["peer"] = sock.getpeername()
    except Exception:
        snap["peer"] = None
    try:
        snap["sock"] = sock.getsockname()
    except Exception:
        snap["sock"] = None
    try:
        snap["closed_attr"] = getattr(sock, "_closed", None)
    except Exception:
        snap["closed_attr"] = None

    return snap

def set_rcon_config(
    host: str,
    port: int,
    password: str,
    timeout: float = 2.5,
    *,
    rcon_connection_logging: bool | None = None,
    rcon_log_dir: str | os.PathLike | None = None,
    rcon_log_file_prefix: str = "rcon_connection",
):
    """
    Configure connection settings and (re)connect.

    Added (optional) kwargs:
      - rcon_connection_logging: enable dedicated RCON connection logging
      - rcon_log_dir: directory for the dated log file
      - rcon_log_file_prefix: filename prefix for the log
    """
    global _CFG, RCON_CLIENT

    if rcon_connection_logging is not None:
        configure_rcon_connection_logging(
            enabled=bool(rcon_connection_logging),
            log_dir=rcon_log_dir,
            file_prefix=rcon_log_file_prefix,
        )

    _CFG.update({"host": host, "port": port, "password": password, "timeout": timeout})

    _rcon_log(
        "INFO",
        "set_rcon_config called",
        host=host,
        port=port,
        timeout=timeout,
        logging_enabled=_RCON_CONN_LOG_ENABLED,
        log_path=get_rcon_connection_log_path(),
    )

    with _RCON_LOCK:
        if RCON_CLIENT:
            _rcon_log("INFO", "Disconnecting existing RCON client before re-connect", **_socket_snapshot(RCON_CLIENT))
            try:
                RCON_CLIENT.stop()
            except Exception as e:
                _rcon_log("ERROR", "Error during disconnect (ignored)", exc_type=type(e).__name__, exc=str(e))
            RCON_CLIENT = None

    _connect()


def _connect():
    """(Re)connect the client. Uses socket timeouts (thread-safe)."""
    global RCON_CLIENT

    host = _CFG.get("host")
    port = _CFG.get("port")
    timeout = _CFG.get("timeout")

    _rcon_log("INFO", "Connecting RCON client", host=host, port=port, timeout=timeout, thread=threading.current_thread().name)

    t0 = time.perf_counter()
    try:
        c = RCONClient(host, port=port, timeout=timeout)
        ok = c.login(_CFG.get("password"))
        if ok is False:
            raise PermissionError("RCON login failed (bad password?)")
        dt_ms = int((time.perf_counter() - t0) * 1000)

        RCON_CLIENT = c
        _rcon_log(
            "INFO",
            "RCON connect success",
            elapsed_ms=dt_ms,
            host=host,
            port=port,
            timeout=timeout,
            **_socket_snapshot(RCON_CLIENT),
        )
    except Exception as e:
        dt_ms = int((time.perf_counter() - t0) * 1000)
        _rcon_log(
            "ERROR",
            "RCON connect failed",
            elapsed_ms=dt_ms,
            exc_type=type(e).__name__,
            exc=str(e),
            host=host,
            port=port,
            timeout=timeout,
        )
        try:
            # Best-effort cleanup if a partially-open client exists
            c.stop()
        except Exception:
            pass
        RCON_CLIENT = None

def _safe_error(msg: str) -> str:
    return f"[RCON Error] {msg}"


def _send_rcon_command(cmd: str) -> str:
    """
    Safe RCON call.
    Rule: ANY failure poisons the client → drop it → reconnect once → retry once.
    No stale sockets are ever reused.

    NOTE: Behavior intentionally unchanged; this only adds logging.
    """
    global RCON_CLIENT

    attempt_id = next(_RCON_ATTEMPT_ID)
    cmd_len = len(cmd) if isinstance(cmd, str) else None

    with _RCON_LOCK:
        _rcon_log(
            "DEBUG",
            "RCON command start",
            attempt_id=attempt_id,
            cmd_len=cmd_len,
            cmd=cmd,  # keep raw for debugging (yes it can be noisy; that's the point here)
            host=_CFG.get("host"),
            port=_CFG.get("port"),
            timeout=_CFG.get("timeout"),
            client_present=RCON_CLIENT is not None,
            **_socket_snapshot(RCON_CLIENT),
        )

        # Ensure we have a client
        if RCON_CLIENT is None:
            _rcon_log("INFO", "No client present; calling _connect()", attempt_id=attempt_id)
            _connect()
            if RCON_CLIENT is None:
                _rcon_log("ERROR", "Not connected after _connect()", attempt_id=attempt_id)
                return _safe_error("Not connected.")

        # First attempt
        t0 = time.perf_counter()
        try:
            res = RCON_CLIENT.command(cmd)
            dt_ms = int((time.perf_counter() - t0) * 1000)
            _rcon_log(
                "DEBUG",
                "RCON command success (attempt 1)",
                attempt_id=attempt_id,
                elapsed_ms=dt_ms,
                result_len=len(res) if isinstance(res, str) else None,
                result_preview=(res[:200] + "...") if isinstance(res, str) and len(res) > 200 else res,
                **_socket_snapshot(RCON_CLIENT),
            )
            return res

        except Exception as e:
            dt_ms = int((time.perf_counter() - t0) * 1000)
            _rcon_log(
                "ERROR",
                "RCON command failed (attempt 1) — poisoning client",
                attempt_id=attempt_id,
                elapsed_ms=dt_ms,
                exc_type=type(e).__name__,
                exc=str(e),
                **_socket_snapshot(RCON_CLIENT),
            )

            # ANY exception = client is invalid
            try:
                RCON_CLIENT.stop()
            except Exception as e_disc:
                _rcon_log("ERROR", "Disconnect failed after error (ignored)", attempt_id=attempt_id, exc_type=type(e_disc).__name__, exc=str(e_disc))

            RCON_CLIENT = None

            # One clean reconnect attempt
            _rcon_log("INFO", "Reconnect attempt after failure", attempt_id=attempt_id)
            _connect()
            if RCON_CLIENT is None:
                _rcon_log(
                    "ERROR",
                    "Reconnect failed",
                    attempt_id=attempt_id,
                    original_exc_type=type(e).__name__,
                    original_exc=str(e),
                )
                return _safe_error(f"Reconnect failed: {type(e).__name__}: {e}")

            # Second attempt
            t1 = time.perf_counter()
            try:
                res2 = RCON_CLIENT.command(cmd)
                dt2_ms = int((time.perf_counter() - t1) * 1000)
                _rcon_log(
                    "DEBUG",
                    "RCON command success (attempt 2)",
                    attempt_id=attempt_id,
                    elapsed_ms=dt2_ms,
                    result_len=len(res2) if isinstance(res2, str) else None,
                    result_preview=(res2[:200] + "...") if isinstance(res2, str) and len(res2) > 200 else res2,
                    **_socket_snapshot(RCON_CLIENT),
                )
                return res2

            except Exception as e2:
                dt2_ms = int((time.perf_counter() - t1) * 1000)
                _rcon_log(
                    "ERROR",
                    "RCON command failed (attempt 2) — giving up and clearing client",
                    attempt_id=attempt_id,
                    elapsed_ms=dt2_ms,
                    exc_type=type(e2).__name__,
                    exc=str(e2),
                    **_socket_snapshot(RCON_CLIENT),
                )
                try:
                    RCON_CLIENT.stop()
                except Exception as e_disc2:
                    _rcon_log("ERROR", "Disconnect failed after second error (ignored)", attempt_id=attempt_id, exc_type=type(e_disc2).__name__, exc=str(e_disc2))
                RCON_CLIENT = None
                return _safe_error(f"{type(e2).__name__}: {e2}")


# ----------------------------
# Convenience wrappers (unchanged signatures)
# ----------------------------
def rcon_list():
    res = _send_rcon_command("list")
    if not res or "RCON Error" in res:
        return 0, []
    # Paper/Vanilla typical: "There are X of a max of Y players online: a, b, c"
    parts = res.split(":", 1)
    count_players = 0
    try:
        import re
        m = re.search(r"There are\s+(\d+)", res)
        if m:
            count_players = int(m.group(1))
    except Exception:
        pass
    players = []
    if len(parts) == 2 and parts[1].strip():
        players = [p.strip() for p in parts[1].split(",") if p.strip()]
    return count_players, players


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


# ----------------------------
# Optional CLI (purely for debugging; does not affect import usage)
# ----------------------------
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="mc_rcon_beta debug runner")
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--password", required=True)
    p.add_argument("--timeout", type=float, default=2.5)

    p.add_argument("--rcon-connection-logging", action="store_true")
    p.add_argument("--rcon-log-dir", default=None)
    p.add_argument("--rcon-log-prefix", default="rcon_connection")

    p.add_argument("--cmd", default="list", help="RCON command to run (default: list)")
    args = p.parse_args()

    set_rcon_config(
        args.host,
        args.port,
        args.password,
        args.timeout,
        rcon_connection_logging=args.rcon_connection_logging,
        rcon_log_dir=args.rcon_log_dir,
        rcon_log_file_prefix=args.rcon_log_prefix,
    )

    out = _send_rcon_command(args.cmd)
    print(out)

