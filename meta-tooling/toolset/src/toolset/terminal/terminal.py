import subprocess
import psutil
import os
import time
from typing import Annotated, Optional
import libtmux

from core import tool, toolset, namespace

namespace()

@toolset()
class Terminal:
    def __init__(self):
        self.server = libtmux.Server()

    @tool()
    def list_sessions(self) -> list:
        """List terminal sessions."""
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        return session_ids

    @tool()    
    def kill_session(self, session_id: int):
        """kill a session"""
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        session.kill()

    @tool()
    def new_session(self) -> int:
        """Open a new terminal window as a new session."""
        session = self.server.new_session(attach=False, start_directory="/home/ubuntu/Workspace")
        session.set_option('status', 'off')
        session_id = session.session_id.replace('$', '')
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        if not os.getenv('NO_VISION'):
            xfce4_terminal_running = any('xfce4-terminal' in p.name() for p in psutil.process_iter())
            proc = subprocess.Popen(["xfce4-terminal", "--title", f"AI-Terminal-{session_id}", "--command", f"tmux attach-session -t {session_id}", "--hide-scrollbar"])
            if xfce4_terminal_running:
                proc.wait()
            else:
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
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        return '\n'.join(session.windows[0].panes[0].capture_pane(start, end))

    @tool()
    def send_keys(self, session_id: int, keys: Annotated[str,"Text or input into terminal window"], enter: Annotated[bool,"Send enter after sending the input."]) -> str:
        """
        Send keys to a terminal session by session id.

        Examaple:
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

            After execution, it will wait for 1 second before returning the result. If the command is not completed at this time, you need to call the relevant function again to view the pane output
        """
        session_ids = [session.session_id.replace('$', '') for session in self.server.sessions]
        sessions = self.server.sessions.filter(session_id=f"${session_id}")
        if not sessions:
            return f"No session found with id: {session_id}. Here are session ids: {', '.join(session_ids)}"
        session = sessions[0]
        session.windows[0].panes[0].send_keys(keys, enter=enter)
        time.sleep(1)
        return '\n'.join(session.windows[0].panes[0].capture_pane())

