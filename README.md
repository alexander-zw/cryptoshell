# cryptoshell

A user-friendly tool for cryptography-related uses. Run `main.py` to start interactive shell.

Currently contains commands to sign and verify RSA signatures. Uses the PKCS#1 v1.5 signature scheme (RSASP1). Only ASCII messages are supported.

The shell supports the following commands:

```
help: help [cmd]
    List available commands if no argument given, otherwise display detailed
    help for command CMD.

exit: exit
    Exit the application. Shorthand: q or Ctrl-D.

rsagen: rsagen [file] [-f pub_file pri_file] [-b] [-c]
    Generates a pair of RSA keys. If FILE is given, writes the results to
    two files whose names are determined by appending "_public_key.pem"
    and "_private_key.pem" to FILE. If -f is used, uses PUB_FILE and
    PRI_FILE as the filenames (appended with .pem extension). If -b is used,
    the bianry (PEM format) signature is printed, otherwise only the specific
    n, e, and d are given. The -c option causes the keys to be printed in
    Python-friendly format.

rsasign: rsasign [-k keyfile] [-m messagefile] [-b] [-c]
    Signs a message with RSA. If KEYFILE is given, uses that file as the
    private key; otherwise prompts for private key. If MESSAGEFILE is
    given, signs the contents of that file; otherwise prompts for message.
    The -b option allows the user to provide the private key in binary PEM
    format; otherwise the prompt asks for exact values of n, e, and d in
    hex. The -c option causes the signature to be printed in Python-friendly
    format.

rsaverify: rsaverify [-k keyfile] [-m messagefile] [-b]
    Verifies an RSA signature on a message. Always prompts for signature in
    hex. If KEYFILE is given, uses that file as the public key; otherwise
    prompts for public key. If MESSAGEFILE is given, verifies the contents
    of that file; otherwise prompts for message. The -b option allows the user
    to provide the public key in binary PEM format; otherwise the prompt asks
    for exact values of n and e in hex.
```
