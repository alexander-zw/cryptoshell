"""
Run this file to start the interactive shell.

This file implements the shell commands.
"""
from cmd import Cmd

class CryptoShell(Cmd):
    prompt = "cs> "
    intro = "========================================\n" \
            "CryptoShell\n" \
            "========================================\n" \
            "Welcome! How may I help you today?"

    def do_exit(self, inp):
        print("May your day be filled with confidentiality, integrity, and availability!")
        return True

    def help_exit(self):
        print("Exit the application. Shorthand: q or Ctrl-D")

    do_q = do_exit
    help_q = help_exit
    do_EOF = do_exit
    help_EOF = help_exit

    def do_add(self, inp):
        """Add a new entry to the system."""
        print("Adding '{}'".format(inp))

CryptoShell().cmdloop()
