import os
from pathlib import Path
from typing import Annotated, List
from core import tool, toolset, namespace

namespace()

NOTE_DIR =  os.path.join(Path.home(), "Workspace/notes")

@toolset()
class Note:
    """
    A toolset for AI Agent to manage persistent notes for state tracking,
    information gathering, and long-term memory across different execution steps.
    """
    def __init__(self):
        os.makedirs(NOTE_DIR, exist_ok=True)

    def _get_filepath(self, title: str) -> str:
        """Sanitize title and return full file path."""
        # Simple sanitization: replace non-alphanumeric/space/hyphen with underscore
        safe_title = "".join(c if c.isalnum() or c in (' ', '-') else '_' for c in title).strip()
        if not safe_title:
            safe_title = "untitled_note"
        return os.path.join(NOTE_DIR, f"{safe_title}.md")

    @tool()
    def save_note(
        self,
        title: Annotated[str, "A concise, unique title for the note."],
        content: Annotated[str, "The content of the note (Markdown format is recommended)."]
    ) -> str:
        """
        Saves a new note or overwrites an existing note with the given title.
        The note is saved to a persistent file for later retrieval.
        """
        filepath = self._get_filepath(title)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return f"Note '{title}' successfully saved to {filepath}"
        except Exception as e:
            return f"Error saving note '{title}': {e}"

    @tool()
    def read_note(
        self,
        title: Annotated[str, "The title of the note to read."]
    ) -> str:
        """
        Reads and returns the content of the note with the given title.
        Returns an error message if the note is not found.
        """
        filepath = self._get_filepath(title)
        if not os.path.exists(filepath):
            return f"Error: Note '{title}' not found. Use list_notes() to see available titles."
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return content
        except Exception as e:
            return f"Error reading note '{title}': {e}"

    @tool()
    def list_notes(self) -> List[str]:
        """
        Lists all available note titles.
        """
        try:
            notes = [f.replace('.md', '') for f in os.listdir(NOTE_DIR) if f.endswith('.md')]
            return notes
        except Exception as e:
            return [f"Error listing notes: {e}"]
