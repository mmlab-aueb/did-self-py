from did_self import DID_Self
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import json


did_self = DID_Self()
key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_dict = key.export(private_key=False, as_dict=True)
did = "did:self:" + key_dict['x'] 
did_document = {
    'controller': did
}

jws_payload = {
    'did': did,
    'controller': did
}

proof = jws.JWS(json.dumps(jws_payload).encode('utf-8'))
proof.add_signature(key, None,
                           json_encode({"alg": "EdDSA"}),
                           None)

proof_64c = proof.serialize(compact=True)

did_self.create(did, json.dumps(did_document), proof_64c)


