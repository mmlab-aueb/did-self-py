from did_self import registry
from did_self.util import prepare_self_did_proof_payload, validate_proof_chain
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import json
import time

registry = registry.DIDSelfRegistry()
# Invoke the create method
# Generate DID and initial secret key
start_time = time.time()
key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
stop_time = time.time()
print (f'{stop_time - start_time} \t key generated')
key_dict = key.export(private_key=False, as_dict=True)
# Generate the DID document
did = "did:self:" + key_dict['x'] 
did_document = {
    'id': did,
    'controller': did,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'controller': did,
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_dict['x'],
            'kty': 'OKP',
        }
    }],
    
}
jws_payload = prepare_self_did_proof_payload(did_document)
start_time = time.time()
proof = jws.JWS(jws_payload.encode('utf-8'))
proof.add_signature(key, None, json_encode({"alg": "EdDSA"}),None)
proof_64c = proof.serialize(compact=True)
stop_time = time.time()
print (f'{stop_time - start_time} \t JWS generated')
print (len(proof_64c), "\t Length of proof")
registry.create(json.dumps(did_document), proof_64c)

# Update the DID document
key_v1 = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_v1_dict = key_v1.export(private_key=False, as_dict=True)
did_document = {
    'id': did,
    'controller': "did:self:" + key_v1_dict['x'],
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'controller': did,
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_v1_dict['x'],
            'kty': 'OKP',
        }
    }]
}
jws_payload = prepare_self_did_proof_payload(did_document)
proof = jws.JWS(jws_payload.encode('utf-8'))
# Note the roof MUST be singed with the key of the previous controller
proof.add_signature(key, None, json_encode({"alg": "EdDSA"}),None)
proof_64c = proof.serialize(compact=True)
registry.update(json.dumps(did_document), proof_64c)

# Update again the DID document
key_v2 = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_v2_dict = key_v1.export(private_key=False, as_dict=True)
did_document = {
    'id': did,
    'controller': "did:self:" + key_v2_dict['x'],
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'controller': did,
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_v2_dict['x'],
            'kty': 'OKP',
        }
    }]
}
jws_payload = prepare_self_did_proof_payload(did_document)
proof = jws.JWS(jws_payload.encode('utf-8'))
# Note the roof MUST be singed with the key of the previous controller
proof.add_signature(key_v1, None, json_encode({"alg": "EdDSA"}),None)
proof_64c = proof.serialize(compact=True)
registry.update(json.dumps(did_document), proof_64c)

# Invoke the read method
document, proof_chain = registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("Proof chain:")
print(json.dumps(proof_chain, indent=2))
# Verify proof chain
try:
    validate_proof_chain(did, document, proof_chain)
    print("The proof chain is valid")
except:
    print("The proof chain is not valid")


