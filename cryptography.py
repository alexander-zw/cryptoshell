"""
A user-friendly tool for cryptography-related uses. Only ASCII messages are
supported.

Signature: Using PKCS#1 v1.5 signature scheme (RSASP1), generates key pairs
and allows users to sign ASCII messages with given key and verify messages
with given key and signature.
"""
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

example_pub_key_file_name = "examples/public_key.pem"
example_pri_key_file_name = "examples/private_key.pem"

def rsa_key_gen(file_names=None, print_binary=False, code_friendly=False):
    """
    Returns an RSA key pair for signing in addition to printout.
    Saves them to the default file.
    """
    print("Generating a pair of RSA keys...")

    key_pair = RSA.generate(bits=1024)
    print(f"Your public key is\n(n={hex(key_pair.n)}, e={hex(key_pair.e)})")
    print("Publicly establish this key as belonging to you.\n")
    print(f"Your private key is\n(n={hex(key_pair.n)}, d={hex(key_pair.d)})")
    print("Do not reveal this key (the d value) to anyone.\n")

    if file_names:
        pub_file_name, pri_file_name = file_names
        with open(pub_file_name, 'wb+') as f1:
            f1.write(key_pair.publickey().export_key('PEM'))
            with open(pri_file_name, 'wb+') as f2:
                f2.write(key_pair.export_key('PEM'))
                print(f"Your public key has been saved to the file {pub_file_name}, "
                      f"and you private key to {pri_file_name}. Do not share the private "
                      "key file with anyone.\n")

    if print_binary:
        print("Binary (PEM) format of public key:")
        print(key_pair.publickey().export_key('PEM').decode('ASCII'))
        print("\nBinary (PEM) format of public key:")
        print(key_pair.export_key('PEM').decode('ASCII'))
        print()

    if code_friendly:
        print("Python-friendly ouput:\n")
        print(f"n = {hex(key_pair.n)}")
        print(f"e = {hex(key_pair.e)}")
        print(f"d = {hex(key_pair.d)}")
        print(f"public_key = Crypto.PublicKey.RSA.construct((n, e))")
        print(f"private_key = Crypto.PublicKey.RSA.construct((n, e, d))\n")
    return key_pair

def rsa_sign(message, private_key, code_friendly=False):
    """ Returns the RSA signature in addition to printout. """
    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1).
    msg_hash = SHA256.new(message)
    signer = PKCS115_SigScheme(private_key)
    signature = signer.sign(msg_hash)
    decoded_signature = binascii.hexlify(signature).decode('ASCII')
    print(f"Your signature is\n{decoded_signature}")
    print("Share this signature along with your message to prove its authenticity.\n")

    if code_friendly:
        print("Python-friendly ouput:\n")
        for i in range(len(decoded_signature) // 64):
            print(f"b\"{decoded_signature[i * 64:(i + 1) * 64]}\"")
        print()
    return signature

def rsa_verify(message, signature, public_key):
    """ Returns if the RSA signature is valid in addition to printout. """
    # Verify PKCS#1 v1.5 signature (RSAVP1).
    msg_hash = SHA256.new(message)
    verifier = PKCS115_SigScheme(public_key)
    try:
        verifier.verify(msg_hash, signature)
        print("Signature is VALID ✅\n")
        return True
    except:
        print("Signature is INVALID ❌\n")
        return False

def read_key_from_file(filename):
    with open(filename, 'r') as f:
        return RSA.import_key(f.read())

def prompt_for_key(public=True, binary=False):
    if binary:
        key_description = "PUBLIC" if public else "RSA PRIVATE"
        print("Please provide the private key in binary (PEM format), including the '-----BEGIN "
              f"{key_description} KEY-----' and '-----END {key_description} KEY-----' tags:")
        key = RSA.import_key(input())
    else:
        print("Please provide the private key in hex (without the '0x').")
        n = int(input("n="), 16)
        e = int(input("e="), 16)
        if public:
            key = RSA.construct((n, e))
        else:
            d = int(input("d="), 16)
            key = RSA.construct((n, e, d))
    return key

def read_message_from_file(filename):
    """ Reads the file and returns the messaged encoded from ASCII to bytes. """
    with open(filename, 'r') as f:
        return bytes(f.read(), "ASCII")

def prompt_for_message():
    print("Please enter the message (the final newline is NOT part of the message):")
    return bytes(input(), "ASCII")

def prompt_for_signature():
    print("Please enter the signature in hex:")
    return binascii.unhexlify(input())

if __name__ == "__main__":
    """
    The following demo uses existing keys and signature to verify a message.
    If GEN_KEY is true, generates a key pair.
    Otherwise uses existing key pair in examples/ to verify.
    """
    GEN_NEW_KEY = False

    message = b"I'm glad I'm me, I'm glad I'm me, there's no one else I want to be."

    if GEN_NEW_KEY:
        key_pair = rsa_key_gen((example_pub_key_file_name, example_pri_key_file_name))
        public_key = key_pair.publickey()
        signature = rsa_sign(message, key_pair)
    else:
        # If strings, reads from file.
        public_key, key_pair = example_pub_key_file_name, example_pri_key_file_name
        signature = binascii.unhexlify(
            b"9450d44ba8b59c949c848a755dcb1683c1596d56e4efb2b7159bdc0853d4cd3a"
            b"14361bebb6204c1b3ecfd8981ab242055b4d846f1cd1e94d6a4277a0d455603c"
            b"1fd70a2293acee0ae47aa621a1977353c70ae0a43393a8a523b2c2ad08dcdc79"
            b"3e46a2a29130f2c556ffaae9620f828556d53c2a3bf27bd6a3d2af2e38b64710"
        )
    assert rsa_verify(message, signature, public_key)
    assert not rsa_verify(b"I hate you.", signature, public_key)
