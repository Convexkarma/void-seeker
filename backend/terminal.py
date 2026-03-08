"""
AutoRecon - terminal.py
PTY terminal WebSocket handler — full interactive shell in the browser.
Each connection gets a real /bin/bash PTY subprocess.
"""

import asyncio
import fcntl
import json
import os
import pty
import signal
import struct
import termios
from typing import Dict, Optional

from fastapi import WebSocket, WebSocketDisconnect


class PTYSession:
    """A single PTY session connected to a real shell process."""

    def __init__(self, session_id: str, cols: int = 220, rows: int = 50):
        self.session_id = session_id
        self.pid: Optional[int] = None
        self.master_fd: Optional[int] = None
        self.cols = cols
        self.rows = rows
        self.alive = False

    def start(self) -> None:
        shell = os.environ.get("SHELL", "/bin/bash")
        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:
            os.execvpe(shell, [shell, "--login"], self._build_env())
        else:
            self.alive = True
            self._set_winsize(self.rows, self.cols)
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def _build_env(self) -> dict:
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env["LANG"] = env.get("LANG", "en_US.UTF-8")
        go_bin = os.path.expanduser("~/go/bin")
        local_bin = os.path.expanduser("~/.local/bin")
        path_parts = env.get("PATH", "").split(":")
        for p in [go_bin, local_bin, "/usr/local/bin", "/usr/bin", "/bin"]:
            if p not in path_parts:
                path_parts.insert(0, p)
        env["PATH"] = ":".join(path_parts)
        return env

    def _set_winsize(self, rows: int, cols: int) -> None:
        if self.master_fd is not None:
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            except OSError:
                pass

    def resize(self, rows: int, cols: int) -> None:
        self.rows, self.cols = rows, cols
        self._set_winsize(rows, cols)
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def write(self, data: bytes) -> None:
        if self.master_fd is not None and self.alive:
            try:
                os.write(self.master_fd, data)
            except OSError:
                self.alive = False

    def read(self) -> bytes:
        if self.master_fd is None or not self.alive:
            return b""
        try:
            return os.read(self.master_fd, 65536)
        except BlockingIOError:
            return b""
        except OSError:
            self.alive = False
            return b""

    def is_alive(self) -> bool:
        if not self.alive or self.pid is None:
            return False
        try:
            result = os.waitpid(self.pid, os.WNOHANG)
            if result[0] != 0:
                self.alive = False
                return False
        except ChildProcessError:
            self.alive = False
            return False
        return True

    def kill(self) -> None:
        self.alive = False
        if self.pid:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(self.pid, sig)
                    os.waitpid(self.pid, os.WNOHANG)
                    break
                except (ProcessLookupError, ChildProcessError):
                    break
            self.pid = None
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


class TerminalManager:
    """Manages multiple PTY sessions, one per WebSocket connection."""

    def __init__(self):
        self.sessions: Dict[str, PTYSession] = {}

    async def handle(self, websocket: WebSocket, session_id: str) -> None:
        session = PTYSession(session_id)
        try:
            session.start()
        except Exception as exc:
            try:
                await websocket.send_bytes(f"\r\n\033[31m[!] Failed to start terminal: {exc}\033[0m\r\n".encode())
            except Exception:
                pass
            return

        self.sessions[session_id] = session

        async def pty_reader():
            try:
                while session.is_alive():
                    data = session.read()
                    if data:
                        await websocket.send_bytes(data)
                    else:
                        await asyncio.sleep(0.01)
            except Exception:
                pass

        async def ws_reader():
            try:
                while True:
                    msg = await websocket.receive()
                    if msg["type"] == "websocket.disconnect":
                        break
                    if "bytes" in msg and msg["bytes"]:
                        session.write(msg["bytes"])
                    elif "text" in msg and msg["text"]:
                        try:
                            data = json.loads(msg["text"])
                            mtype = data.get("type", "")
                            if mtype == "resize":
                                session.resize(max(1, int(data.get("rows", 24))), max(1, int(data.get("cols", 80))))
                            elif mtype == "input":
                                session.write(data["data"].encode("utf-8"))
                            elif mtype == "ping":
                                await websocket.send_text(json.dumps({"type": "pong"}))
                        except (json.JSONDecodeError, KeyError, ValueError):
                            session.write(msg["text"].encode("utf-8"))
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        reader_task = asyncio.create_task(pty_reader())
        writer_task = asyncio.create_task(ws_reader())

        try:
            await asyncio.wait({reader_task, writer_task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (reader_task, writer_task):
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            session.kill()
            self.sessions.pop(session_id, None)

    def get_session(self, session_id: str) -> Optional[PTYSession]:
        return self.sessions.get(session_id)

    def list_sessions(self) -> list:
        return [{"session_id": sid, "alive": s.is_alive(), "pid": s.pid, "cols": s.cols, "rows": s.rows} for sid, s in self.sessions.items()]

    def kill_session(self, session_id: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id].kill()
            del self.sessions[session_id]

    def kill_all(self) -> None:
        for s in list(self.sessions.values()):
            s.kill()
        self.sessions.clear()
