"""PTY WebSocket handler — connects xterm.js in the browser to a real shell."""

import asyncio
import os
import signal
import struct
import fcntl
import termios

from fastapi import WebSocket


class PtySession:
    """Manages a single PTY session connected to a WebSocket."""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.master_fd = None
        self.pid = None

    async def start(self):
        """Fork a PTY and start reading/writing loops."""
        pid, fd = os.forkpty()

        if pid == 0:
            # Child process — exec a shell
            shell = os.environ.get("SHELL", "/bin/bash")
            os.execvpe(shell, [shell, "--login"], os.environ)
        else:
            # Parent process
            self.pid = pid
            self.master_fd = fd

            # Set non-blocking
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Run read/write concurrently
            await asyncio.gather(
                self._read_loop(),
                self._write_loop(),
            )

    async def _read_loop(self):
        """Read from PTY master and send to WebSocket."""
        loop = asyncio.get_event_loop()
        try:
            while True:
                await asyncio.sleep(0.01)
                try:
                    data = os.read(self.master_fd, 4096)
                    if data:
                        await self.ws.send_text(data.decode("utf-8", errors="replace"))
                except (OSError, BlockingIOError):
                    pass
        except Exception:
            pass
        finally:
            self.cleanup()

    async def _write_loop(self):
        """Read from WebSocket and write to PTY master."""
        try:
            while True:
                data = await self.ws.receive_text()
                if data and self.master_fd:
                    os.write(self.master_fd, data.encode("utf-8"))
        except Exception:
            pass
        finally:
            self.cleanup()

    def resize(self, rows: int, cols: int):
        """Resize the PTY."""
        if self.master_fd:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)

    def cleanup(self):
        """Kill the child process and close the master fd."""
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.pid = None
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


# Track active terminal sessions
terminal_sessions: dict[str, PtySession] = {}


async def handle_terminal_ws(ws: WebSocket, terminal_id: str):
    """Handle a terminal WebSocket connection."""
    await ws.accept()
    session = PtySession(ws)
    terminal_sessions[terminal_id] = session

    try:
        await session.start()
    finally:
        terminal_sessions.pop(terminal_id, None)
        session.cleanup()
