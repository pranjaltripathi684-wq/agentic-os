"""
Run Agentic OS from the project folder without installing it:

    python main.py "How much free disk space do I have?"     # same as: agentos run "..."
    python main.py chat | tui | dashboard | audit verify | ...

After `pip install -e .` the same commands are available as `agentos ...`.
"""

from agentos.cli import main

if __name__ == "__main__":
    main()
