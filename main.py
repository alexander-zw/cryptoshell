"""
Run this file to start the interactive shell.

This file implements the shell commands.
"""
from cmd import Cmd
import shlex
import cryptography

class CryptoShell(Cmd):
    prompt = "cs> "
    intro = "========================================\n" \
            "CryptoShell\n" \
            "========================================\n" \
            "Welcome! How may I help you today?"

    def help_help(self):
        print("help: help [cmd]")
        print("    List available commands if no argument given, otherwise display detailed")
        print("    help for command CMD.")

    def do_exit(self, inp):
        print("May your day be filled with confidentiality, integrity, and availability!")
        return True

    def help_exit(self):
        print("exit: exit")
        print("    Exit the application. Shorthand: q or Ctrl-D.")

    do_q = do_exit
    help_q = help_exit
    do_EOF = do_exit
    help_EOF = help_exit

    def do_rsagen(self, inp):
        tokenizer = Tokenizer(inp)
        file_names = None
        if tokenizer.has_option('n'): # Both file names are given.
            file_names = [name + '.pem' for name in tokenizer.get_option_args('n', 2)]
        else: # One name is given, we need to adapt into two file names.
            args = tokenizer.get_args()
            if args:
                file_names = args[0] + "_public_key.pem", args[0] + "_private_key.pem"
        # Otherwise, no file names are given, no need to write to file.
        code_friendly = tokenizer.has_option('c')

        cryptography.rsa_key_gen(file_names=file_names, code_friendly=code_friendly)

    def help_rsagen(self):
        print("rsagen: rsagen [file] [-n pub_file pri_file] [-c]")
        print("    Generates a pair of RSA keys. If FILE is given, writes the results to")
        print("    two files whose names are determined by appending \"_public_key.pem\"")
        print("    and \"_private_key.pem\" to FILE. If -n is used, uses PUB_FILE and")
        print("    PRI_FILE as the filenames (as well as .pem extension). The -c option")
        print("    causes the printout to be in Python-friendly format.")


class Tokenizer:
    def __init__(self, input_str):
        self.tokens = list(shlex.shlex(input_str, punctuation_chars=True))

    def has_option(self, option):
        """
        An option is a token containing 'a' followed by a letter. Returns whether the
        tokenizer detected an option '-OPTION'.
        """
        return ('-' + option) in self.tokens

    def get_option_args(self, option, num_args):
        """ Returns a list of the arguments for an option. """
        first_arg_ind = self.tokens.index('-' + option) + 1
        return self.tokens[first_arg_ind:first_arg_ind + num_args]

    def get_args(self):
        """
        An argument is any token not starting with '-'. Returns a list of all arguments.
        """
        return [token for token in self.tokens if token[0] != '-']

CryptoShell().cmdloop()
