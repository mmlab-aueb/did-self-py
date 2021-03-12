from jwcrypto.common import  base64url_decode, base64url_encode
from jwcrypto import jwk
import base58

def did_to_jwk(did:str)->jwk.JWK:
    if (did.startswith("did:self:")): #Used only for the first signature of the proof chain
        public_key = did.split(":")[2]
    if (did.startswith("did:key:z6MK")): #Ed25519 public key encoded using base58
        public_key_58 = did.split(":")[2][4:]
        public_key = base64url_encode(base58.b58decode(public_key_58))
    key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': public_key}
    return jwk.JWK(**key_dict)

def Ed25519_to_didkey(base64key:str):
    return "did:key:z6MK" + base58.b58encode(base64url_decode(base64key)).decode()
