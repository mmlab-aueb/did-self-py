import hashlib
from jwcrypto.common import json_encode, base64url_encode
import json
from jwcrypto import jwk, jws


def prepare_self_did_proof_payload(did_document):
    documet_sha256 = hashlib.sha256()
    documet_sha256.update(json.dumps(did_document).encode('utf-8'))
    jws_payload = {
        'id': did_document['id'],
        'controller': did_document['controller'],
        'sha-256': base64url_encode(documet_sha256.digest())
    }
    return json.dumps(jws_payload)

def validate_proof_chain(did, did_document, proof_chain):
    _did = did
    _controller = did
    for proof in proof_chain:
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(proof)
        payload = json.loads(claimed_proof.objects['payload'].decode())
        _id = payload['id']
        if (_id != _did):
            raise Exception("The proof contains an invalid id")
            return -1
        signer = _controller
        signer_key_64 = signer.split(":")[2]
        signer_key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': signer_key_64}
        signer_jwk = jwk.JWK(**signer_key_dict)
        claimed_proof.verify(signer_jwk)
        _controller = payload['controller']
    if (_controller != did_document['controller']):
        raise Exception("The document includes an invalid controller")
        return -1
    #TODO check sha-256
    return True
