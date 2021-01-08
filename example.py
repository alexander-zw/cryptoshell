"""
The following demo uses existing keys and signature to verify a message.
If GEN_KEY is true, generates a key pair.
Otherwise uses existing key pair in this folder to verify.
"""
import cryptography
import binascii

example_pub_key_file_name = "examples/public_key.pem"
example_pri_key_file_name = "examples/private_key.pem"

if __name__ == "__main__":
    GEN_NEW_KEY = False

    message = b"I'm glad I'm me, I'm glad I'm me, there's no one else I want to be."

    if GEN_NEW_KEY:
        key_pair = cryptography.rsa_key_gen((example_pub_key_file_name, example_pri_key_file_name))
        public_key = key_pair.publickey()
        signature = cryptography.rsa_sign(message, key_pair)
    else:
        # If strings, reads from file.
        public_key, key_pair = cryptography.read_key_from_file(example_pub_key_file_name), \
                               cryptography.read_key_from_file(example_pri_key_file_name)
        signature = binascii.unhexlify(
            b"9450d44ba8b59c949c848a755dcb1683c1596d56e4efb2b7159bdc0853d4cd3a"
            b"14361bebb6204c1b3ecfd8981ab242055b4d846f1cd1e94d6a4277a0d455603c"
            b"1fd70a2293acee0ae47aa621a1977353c70ae0a43393a8a523b2c2ad08dcdc79"
            b"3e46a2a29130f2c556ffaae9620f828556d53c2a3bf27bd6a3d2af2e38b64710"
        )
    assert cryptography.rsa_verify(message, signature, public_key)
    assert not cryptography.rsa_verify(b"I hate you.", signature, public_key)
