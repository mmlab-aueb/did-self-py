import hashlib
import json
import datetime
from jwcrypto.common import base64url_encode
from jwcrypto import jwk, jws
from didself.did_util import did_to_jwk

def generate_proof(did_document:list, json_web_key:jwk.JWK, created:str=None):
    documet_sha256 = hashlib.sha256()
    documet_sha256.update(json.dumps(did_document).encode('utf-8'))
    if (not created):
        created = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z'
    jws_payload_dict = {
        'id': did_document['id'],
        'controller': did_document['controller'],
        'created':created,
        'sha-256': base64url_encode(documet_sha256.digest())
    }
    jws_payload = json.dumps(jws_payload_dict)
    proof = jws.JWS(jws_payload.encode('utf-8'))
    proof.add_signature(json_web_key, None, json.dumps({"alg": "EdDSA"}),None)
    return proof

def verify_proof(did_document:list, proof:jws.JWS, signer:str):
    documet_sha256 = hashlib.sha256()
    documet_sha256.update(json.dumps(did_document).encode('utf-8'))
    document_sha256_b64 = base64url_encode(documet_sha256.digest())
    payload = json.loads(proof.objects['payload'].decode())
    if(document_sha256_b64 != payload['sha-256']):
        raise Exception("The sha-256 field of the proof payload is not valid")
        return -1
    signer_jwk = did_to_jwk(signer)
    proof.verify(signer_jwk)

def verify_proof_chain(did, did_document, proof_chain):
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
    signer_jwk = did_to_jwk(did)#----The fist proof must be verified using the DID
    for proof in proof_chain:
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(proof)
        payload = json.loads(claimed_proof.objects['payload'].decode())
        _id = payload['id']
        if (_id != _did): #----All proofs must include DID in their id field
            raise Exception("A proof contains an invalid id")
            return -1
        claimed_proof.verify(signer_jwk)
        signer_jwk = did_to_jwk(payload['controller'])#----The next proof must be verified with this
    return True
