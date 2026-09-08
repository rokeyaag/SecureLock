"""SecureLock Entry Point.
Runs the GUI application by default or routes to CLI if explicit CLI commands are provided.
"""

import sys
import os

# Ensure local modules are found
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

VALID_CLI_COMMANDS = {"lock", "unlock", "reset-password", "list", "-h", "--help"}

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() in VALID_CLI_COMMANDS:
        from cli import run_cli
        run_cli()
    else:
        from gui.app import launch
        launch()

if __name__ == "__main__":
    main()
