"""
AutoRecon - terminal.py
PTY Terminal WebSocket Handler

Provides a full interactive shell in the browser via xterm.js.
Each WebSocket connection gets a real /bin/bash PTY subprocess.
Supports: color output, ANSI/VT100, resize events, multi-session.
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


# ── PTY Session ───────────────────────────────────────────────────────────────

class PTYSession:
    """
    A single PTY (pseudoterminal) session connected to a real shell process.
    The master_fd is used to read/write to the shell.
    """

    def __init__(self, session_id: str, cols: int = 220, rows: int = 50):
        self.session_id = session_id
        self.pid: Optional[int] = None
        self.master_fd: Optional[int] = None
        self.cols = cols
        self.rows = rows
        self.alive = False

    def start(self):
        """Fork a PTY and exec the user's shell."""
        shell = os.environ.get("SHELL", "/bin/bash")
        env = self._build_env()

        # Fork a PTY — returns (child_pid, master_fd)
        self.pid, self.master_fd = pty.fork()

        if self.pid == 0:
            # ── Child process: exec the shell ─────────────────────────────────
            os.execvpe(shell, [shell, "--login"], env)
            # execvpe never returns
        else:
            # ── Parent process: configure the master fd ───────────────────────
            self.alive = True
            # Set initial terminal size
            self._set_winsize(self.rows, self.cols)
            # Make reads non-blocking
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def _build_env(self) -> dict:
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env["LANG"] = env.get("LANG", "en_US.UTF-8")
        # Ensure Go tools are on PATH
        go_bin = os.path.expanduser("~/go/bin")
        local_bin = os.path.expanduser("~/.local/bin")
        path_parts = env.get("PATH", "").split(":")
        for p in [go_bin, local_bin, "/usr/local/bin", "/usr/bin", "/bin"]:
            if p not in path_parts:
                path_parts.insert(0, p)
        env["PATH"] = ":".join(path_parts)
        return env

    def _set_winsize(self, rows: int, cols: int):
        """Send TIOCSWINSZ to update the terminal window size."""
        if self.master_fd is not None:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            except OSError:
                pass

    def resize(self, rows: int, cols: int):
        """Resize the PTY window."""
        self.rows = rows
        self.cols = cols
        self._set_winsize(rows, cols)
        # Send SIGWINCH to notify the shell of the resize
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def write(self, data: bytes):
        """Write keyboard input to the shell."""
        if self.master_fd is not None and self.alive:
            try:
                os.write(self.master_fd, data)
            except OSError:
                self.alive = False

    def read(self) -> bytes:
        """Read available output from the shell (non-blocking)."""
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
        """Check if the child process is still running."""
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

    def kill(self):
        """Kill the shell process and close the master fd."""
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


# ── Terminal Manager ──────────────────────────────────────────────────────────

class TerminalManager:
    """
    Manages multiple PTY sessions, one per WebSocket connection.
    Each browser terminal tab gets its own session_id and PTY process.
    """

    def __init__(self):
        self.sessions: Dict[str, PTYSession] = {}

    async def handle(self, websocket: WebSocket, session_id: str):
        """
        Main handler for a terminal WebSocket connection.
        Starts a PTY, then bridges:
          WebSocket → PTY  (keyboard input)
          PTY → WebSocket  (shell output)
        """
        session = PTYSession(session_id)

        try:
            session.start()
        except Exception as e:
            error_msg = f"\r\n\033[31m[!] Failed to start terminal: {e}\033[0m\r\n"
            try:
                await websocket.send_bytes(error_msg.encode())
            except Exception:
                pass
            return

        self.sessions[session_id] = session

        # Task 1: Read from PTY → send to WebSocket
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

        # Task 2: Read from WebSocket → write to PTY
        async def ws_reader():
            try:
                while True:
                    msg = await websocket.receive()

                    if msg["type"] == "websocket.disconnect":
                        break

                    if "bytes" in msg and msg["bytes"]:
                        # Raw binary input (keyboard data from xterm.js)
                        session.write(msg["bytes"])

                    elif "text" in msg and msg["text"]:
                        # JSON control messages
                        try:
                            data = json.loads(msg["text"])
                            msg_type = data.get("type", "")

                            if msg_type == "resize":
                                rows = max(1, int(data.get("rows", 24)))
                                cols = max(1, int(data.get("cols", 80)))
                                session.resize(rows, cols)

                            elif msg_type == "input":
                                # Text input (fallback)
                                session.write(data["data"].encode("utf-8"))

                            elif msg_type == "ping":
                                await websocket.send_text(json.dumps({"type": "pong"}))

                        except (json.JSONDecodeError, KeyError, ValueError):
                            # Treat as raw text input
                            session.write(msg["text"].encode("utf-8"))

            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        # Run both tasks concurrently
        reader_task = asyncio.create_task(pty_reader())
        writer_task = asyncio.create_task(ws_reader())

        try:
            done, pending = await asyncio.wait(
                {reader_task, writer_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            # Cancel remaining tasks
            for task in (reader_task, writer_task):
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

            # Cleanup
            session.kill()
            self.sessions.pop(session_id, None)

    def get_session(self, session_id: str) -> Optional[PTYSession]:
        return self.sessions.get(session_id)

    def list_sessions(self) -> list:
        return [
            {
                "session_id": sid,
                "alive": s.is_alive(),
                "pid": s.pid,
                "cols": s.cols,
                "rows": s.rows,
            }
            for sid, s in self.sessions.items()
        ]

    def kill_session(self, session_id: str):
        if session_id in self.sessions:
            self.sessions[session_id].kill()
            del self.sessions[session_id]

    def kill_all(self):
        for session in list(self.sessions.values()):
            session.kill()
        self.sessions.clear()
