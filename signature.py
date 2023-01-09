import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public = private.public_key()
    return private, public


def sign(message, private):
    #message = bytes(str(message), 'utf-8') # Converting message to byte
    # or -> message = b"A message I want to sign"
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig


def verify(message, signature, public):
    try:
        public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        print("Error executing public key")
        return False


if __name__ == '__main__':
    (pr, pu) = generate_keys()
    #print(pr)
    #print(pu)
    message = b"hi I am Neelesh Aggarwal"
    signature = sign(message, pr)
    #print(signature)
    verified = verify(message, signature, pu)
    if verified:
        print("Signature Verified Successfully")
    else:
        print("Signature Verification Failed")