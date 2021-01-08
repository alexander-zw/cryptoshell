"""
Run this file to start the interactive shell.

This file implements the shell commands.
"""
import cryptography
from cmd import Cmd
import shlex

class CryptoShell(Cmd):
    prompt = "<cs> "
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
        TWO_NAMES_OPTION = 'f'
        BINARY_OPTION = 'b'
        CODE_FRIENDLY_OPTION = 'c'

        tokenizer = Tokenizer(inp)
        file_names = None
        if tokenizer.has_option(TWO_NAMES_OPTION): # Both file names are given.
            file_names = [name + '.pem' for name in tokenizer.get_option_args(TWO_NAMES_OPTION, 2)]
        else: # One name is given, we need to adapt into two file names.
            args = tokenizer.get_args()
            if args:
                file_names = args[0] + "_public_key.pem", args[0] + "_private_key.pem"
        # Otherwise, no file names are given, no need to write to file.
        binary = tokenizer.has_option(BINARY_OPTION)
        code_friendly = tokenizer.has_option(CODE_FRIENDLY_OPTION)

        cryptography.rsa_key_gen(file_names=file_names, print_binary=binary,
                                 code_friendly=code_friendly)

    def help_rsagen(self):
        print("rsagen: rsagen [file] [-f pub_file pri_file] [-b] [-c]")
        print("    Generates a pair of RSA keys. If FILE is given, writes the results to")
        print("    two files whose names are determined by appending \"_public_key.pem\"")
        print("    and \"_private_key.pem\" to FILE. If -f is used, uses PUB_FILE and")
        print("    PRI_FILE as the filenames (appended with .pem extension). If -b is used,")
        print("    the bianry (PEM format) signature is printed, otherwise only the specific")
        print("    n, e, and d are given. The -c option causes the keys to be printed in")
        print("    Python-friendly format.")

    def do_rsasign(self, inp):
        KEY_FILE_OPTION = 'k'
        MESSAGE_FILE_OPTION = 'm'
        BINARY_KEY_OPTION = 'b'
        CODE_FRIENDLY_OPTION = 'c'

        tokenizer = Tokenizer(inp)
        binary_key = tokenizer.has_option(BINARY_KEY_OPTION)
        if tokenizer.has_option(KEY_FILE_OPTION):
            private_key = tokenizer.get_option_args(KEY_FILE_OPTION, 1)[0]
        else:
            private_key = cryptography.prompt_for_key(public=False, binary=binary_key)
        if tokenizer.has_option(MESSAGE_FILE_OPTION):
            message_file = tokenizer.get_option_args(MESSAGE_FILE_OPTION, 1)[0]
            message = cryptography.read_message_from_file(message_file)
        else:
            print("Please enter the message (the final newline is NOT part of the message):")
            message = bytes(input(), "ASCII")
        code_friendly = tokenizer.has_option(CODE_FRIENDLY_OPTION)

        cryptography.rsa_sign(message, private_key, code_friendly=code_friendly)

    def help_rsasign(self):
        print("rsasign: rsasign [-k keyfile] [-m messagefile] [-b] [-c]")
        print("    Signs a message with RSA. If KEYFILE is given, uses that file as the")
        print("    private key; otherwise prompts for private key. If MESSAGEFILE is")
        print("    given, signs the contents of that file; otherwise prompts for message.")
        print("    The -b option allows the user to provide the private key in binary PEM")
        print("    format; otherwise the prompt asks for exact values of n, e, and d in")
        print("    hex. The -c option causes the signature to be printed in Python-friendly")
        print("    format.")

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

if __name__ == "__main__":
    CryptoShell().cmdloop()
