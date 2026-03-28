import os
import shlex
import subprocess
import time
from typing import Annotated, Optional

import libtmux
import psutil

from core import tool, toolset, namespace
from security_guard import DEFAULT_ALLOWED_HOST_PATTERNS, SecurityViolation, load_security_policy, validate_command

namespace()

@toolset()
class Terminal:
    def __init__(self):
        try:
            self.server = libtmux.Server()
        except Exception:
            self.server = None
        policy = load_security_policy()
        self.allowed_hosts = tuple(policy.get("allowed_host_patterns") or DEFAULT_ALLOWED_HOST_PATTERNS)
        self.default_timeout = int(policy.get("command_timeout_seconds") or 30)

    @tool()
    def list_sessions(self) -> list:
        """List terminal sessions."""
        if not self.server:
            return "[ERROR] tmux server not available"
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        return session_ids

    @tool()
    def kill_session(self, session_id: int):
        """kill a session"""
        if not self.server:
            return "[ERROR] tmux server not available"
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        session.kill()
        return f"Killed session {session_id}"

    @tool()
    def new_session(self, show_gui: Annotated[bool, "Whether to open a visible GUI terminal window for the session."] = False) -> int:
        """Open a new terminal window as a new session."""
        if not self.server:
            return "[ERROR] tmux server not available"
        session = self.server.new_session(attach=False, start_directory="/home/ubuntu/Workspace")
        session.set_option('status', 'off')
        session_id = session.session_id.replace('$', '')
        if show_gui and not os.getenv('NO_VISION'):
            subprocess.Popen([
                "xfce4-terminal",
                "--title",
                f"AI-Terminal-{session_id}",
                "--command",
                f"tmux attach-session -t {session_id}",
                "--hide-scrollbar",
            ])
            time.sleep(0.5)
            session.set_option('destroy-unattached', 'on')
        return int(session_id)

    @tool()
    def get_output(
            self,
            session_id: int,
            start: Annotated[Optional[str],"Specify the starting line number. Zero is the first line of the visible pane. Positive numbers are lines in the visible pane. Negative numbers are lines in the history. - is the start of the history. Default: None"] = "",
            end: Annotated[Optional[str],"Specify the ending line number. Zero is the first line of the visible pane. Positive numbers are lines in the visible pane. Negative numbers are lines in the history. - is the end of the visible pane Default: None"] = ""
        ) -> str:
        """Get the output of a terminal session by session id."""
        if not self.server:
            return "[ERROR] tmux server not available"
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        return '\n'.join(session.windows[0].panes[0].capture_pane(start, end))

    @tool()
    def send_keys(
        self,
        session_id: int,
        keys: Annotated[str,"Text or input into terminal window"],
        enter: Annotated[bool,"Send enter after sending the input."],
        wait_seconds: Annotated[float, "How long to wait before capturing pane output."] = 0.2,
        timeout_seconds: Annotated[int, "Maximum allowed runtime for the entered command."] = 30,
    ) -> str:
        """
        Send keys to a terminal session by session id.

        Example:
            To execute 'whoami' command:
            ```
            import toolset

            toolset.terminal.send_keys(session_id=0, keys="whoami", enter=True)
            ```

            To press Ctrl+c:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-c", enter=False)
            ```

            To press Esc:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-[", enter=False)
            ```

            To press up arrow:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-Up", enter=False)
            ```

            To press tab:
            ```
            toolset.terminal.send_keys(session_id=0, keys="C-i", enter=False)
            ```

            After execution, it will wait for wait_seconds before returning the result. If the command is not completed at this time, you need to call the relevant function again to view the pane output
        """
        if not self.server:
            return "[ERROR] tmux server not available"
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        command_to_send = keys
        if enter:
            try:
                # shlex.quote ensures keys is a single quoted argument to bash -lc,
                # so the security check on the raw keys string is sufficient.
                timeout_seconds = validate_command(keys, self.allowed_hosts, timeout_seconds or self.default_timeout)
                if keys.strip() and not keys.strip().startswith(("C-", "M-", "S-")):
                    command_to_send = f"timeout --foreground {timeout_seconds}s bash -lc {shlex.quote(keys)}"
            except SecurityViolation as exc:
                return f"[SECURITY] {exc}"
        session.windows[0].panes[0].send_keys(command_to_send, enter=enter)
        time.sleep(max(wait_seconds, 0))
        return '\n'.join(session.windows[0].panes[0].capture_pane())

    @tool()
    def run_command(
        self,
        cmd: Annotated[str, "Shell command to run."],
        timeout: Annotated[int, "Execution timeout in seconds."] = 0,
        workdir: Annotated[Optional[str], "Optional working directory."] = None,
    ) -> dict:
        """Run a one-shot shell command and return stdout, stderr, exit code, and timeout status."""
        try:
            timeout = validate_command(cmd, self.allowed_hosts, timeout or self.default_timeout)
        except SecurityViolation as exc:
            return {"stdout": "", "stderr": f"[SECURITY] {exc}", "exit_code": -2, "timed_out": False}
        timed_out = False
        try:
            result = subprocess.run(
                ["bash", "-lc", cmd],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "timed_out": timed_out,
            }
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            return {
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or "",
                "exit_code": -1,
                "timed_out": timed_out,
            }
