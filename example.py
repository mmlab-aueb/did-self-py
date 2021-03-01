from did_self import registry
from did_self.proof_chain import generate_proof, verify_proof_chain
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import json

registry = registry.DIDSelfRegistry()
# DID creation
# Generate DID and initial secret key
key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_dict = key.export(private_key=False, as_dict=True)
# Generate the key for the first controller.
key_v0 = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_v0_dict = key_v0.export(private_key=False, as_dict=True)
# Generate the DID document
did = "did:self:" + key_dict['x'] 
controller = "did:key:u" + key_v0_dict['x']
did_document = {
    'id': did,
    'controller': controller,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_dict['x'],
            'kty': 'OKP',
        }
    }],
    
}

proof = generate_proof(did_document, key)
registry.create(did_document, proof)
#-------------Dumping-------------------
document, proof_chain = registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("Proof chain:")
print(json.dumps(proof_chain, indent=2))
proof = jws.JWS()
proof.deserialize(proof_chain[-1])
payload = json.loads(proof.objects['payload'].decode())
print("Proof payload:")
print(json.dumps(payload, indent=2))

# Update the DID document, change the controller
key_v1 = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_v1_dict = key_v1.export(private_key=False, as_dict=True)
did_document = {
    'id': did,
    'controller': "did:key:u" + key_v1_dict['x'],
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_dict['x'],
            'kty': 'OKP',
        }
    }]
}

# Note the proof MUST be singed with the key of the previous controller
proof = generate_proof(did_document, key_v0)
registry.update(did_document, proof)
#-------------Dumping-------------------
document, proof_chain = registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("Proof chain:")
print(json.dumps(proof_chain, indent=2))
proof = jws.JWS()
proof.deserialize(proof_chain[-1])
payload = json.loads(proof.objects['payload'].decode())
print("Proof payload:")
print(json.dumps(payload, indent=2))

# Update again the DID document, change the authentication key
key_v2 = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_v2_dict = key_v1.export(private_key=False, as_dict=True)
did_document = {
    'id': did,
    'controller': "did:key:u" + key_v1_dict['x'],
    'authentication': [{
        'id': did + '#key2',
        'type': "JsonWebKey2020",
        'publicKeyJwk': {
            'crv': 'Ed25519',
            'x'  : key_v2_dict['x'],
            'kty': 'OKP',
        }
    }]
}
# Note the proof MUST be singed with the key of the previous controller
proof = generate_proof(did_document, key_v1)
registry.update(did_document, proof)
#-------------Dumping-------------------
document, proof_chain = registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("Proof chain:")
print(json.dumps(proof_chain, indent=2))
proof = jws.JWS()
proof.deserialize(proof_chain[-1])
payload = json.loads(proof.objects['payload'].decode())
print("Proof payload:")
print(json.dumps(payload, indent=2))

# Verify proof chain
try:
    verify_proof_chain(did, document, proof_chain)
    print("The proof chain is valid")
except Exception as e:
    print("The proof chain is not valid", e)


