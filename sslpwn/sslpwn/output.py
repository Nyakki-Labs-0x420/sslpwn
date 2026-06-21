"""Output management: terminal printing via Rich and file logging."""
import os
import sys
import signal
from typing import Optional, List
from datetime import datetime
from rich.console import Console
from rich.text import Text

console = Console()


class OutputManager:
    """Handles writing results to a file and to the terminal."""

    def __init__(self, base_filename: str, output_dir: str = ".") -> None:
        self._base = base_filename
        self._dir = output_dir
        self._lines: List[str] = []
        self._finalised = False
        os.makedirs(self._dir, exist_ok=True)
        # Register cleanup on SIGINT / SIGTERM
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def log(self, message: str, level: str = "INFO") -> None:
        """Add a timestamped line and print it."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{level}] {message}"
        self._lines.append(line)
        style = "bold green" if level == "SUCCESS" else "bold yellow" if level == "WARN" else "white"
        console.print(Text(line, style=style))

    def _write_file(self) -> None:
        """Write all accumulated lines to the output file."""
        if not self._lines:
            return
        filename = os.path.join(self._dir, f"{self._base}_sslpwn_results.txt")
        with open(filename, "a", encoding="utf-8") as f:
            for line in self._lines:
                f.write(line + "\n")
        self._lines.clear()

    def finalise(self) -> None:
        """Write remaining lines and mark as done."""
        if not self._finalised:
            self._write_file()
            console.print(f"\n[bold]Results saved to {self._base}_sslpwn_results.txt[/bold]")
            self._finalised = True

    def _handle_signal(self, signum, frame) -> None:
        """Write current results and exit gracefully on Ctrl+C."""
        console.print("\n[bold red]Interrupted. Saving results...[/bold red]")
        self._write_file()
        sys.exit(1)