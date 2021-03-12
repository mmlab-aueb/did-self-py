from didself import registry
from didself.proof_chain import generate_proof, verify_proof_chain
from didself.did_util import Ed25519_to_didkey
from jwcrypto import jwk, jws
import json

registry = registry.DIDSelfRegistry()
# DID creation
# Generate DID and initial secret key
did_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_key_dict = did_key.export_public(as_dict=True)
# Generate the key for the first controller.
controller_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
# Generate the DID document
did = "did:self:" + did_key_dict['x']
controller_key = controller_jwk.export(as_dict=True)['x']
controller = Ed25519_to_didkey(controller_key)
did_document = {
    'id': did,
    'controller': controller,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}

proof = generate_proof(did_document, did_key)
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
controller2_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
controller_key = controller2_jwk.export(as_dict=True)['x']
controller = Ed25519_to_didkey(controller_key)
did_document = {
    'id': did,
    'controller': controller,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}
# Note the proof MUST be singed with the key of the previous controller
proof = generate_proof(did_document, controller_jwk)
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
authnetication_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'controller': controller,
    'authentication': [{
        'id': did + '#key2',
        'type': "JsonWebKey2020",
        'publicKeyJwk': authnetication_key.export_public(as_dict=True)
    }]
}
# Note the proof MUST be singed with the key of the previous controller
proof = generate_proof(did_document, controller2_jwk)
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


