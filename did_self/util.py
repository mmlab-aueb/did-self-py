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
        'version':1,
        'sha-256': base64url_encode(documet_sha256.digest())
    }
    return json.dumps(jws_payload)

def validate_proof_chain(did, did_document, proof_chain):
    #--------------Verify sha-256 in the last proof----------
    documet_sha256 = hashlib.sha256()
    documet_sha256.update(json.dumps(did_document).encode('utf-8'))
    document_sha256_b64 = base64url_encode(documet_sha256.digest())
    last_proof = jws.JWS()
    last_proof.deserialize(proof_chain[-1])
    payload = json.loads(last_proof.objects['payload'].decode())
    if(document_sha256_b64 != payload['sha-256']):
        raise Exception("The sha-256 included in the last proof is not valid")
        return -1
    #--------------Verify the chain of trust---------------
    _did = did
    _controller = "did:key:u" + did.split(":")[2]#----The fist proof must be verified using the DID
    for proof in proof_chain:
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(proof)
        payload = json.loads(claimed_proof.objects['payload'].decode())
        _id = payload['id']
        if (_id != _did): #----All proofs must include DID in their id field
            raise Exception("A proof contains an invalid id")
            return -1
        signer = _controller
        signer_key_64 = signer.split(":")[2][1:]
        signer_key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': signer_key_64}
        signer_jwk = jwk.JWK(**signer_key_dict)
        claimed_proof.verify(signer_jwk)
        _controller = payload['controller']#----The next proof must be verified with this
    return True
