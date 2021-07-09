from didself import registry
from jwcrypto import jwk, jws
import json

# DID creation
# Generate DID and initial secret key
did_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
# Initialize registry
owner_registry = registry.DIDSelfRegistry(did_key)

# Generate the DID document
did_key_dict = did_key.export_public(as_dict=True)
did = "did:self:" + did_key_dict['x']
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}

owner_registry.create(did_document)
#-------------Dumping-------------------
document, proofs = owner_registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
document_proof = jws.JWS()
document_proof.deserialize(proofs[0])
payload = json.loads(document_proof.objects['payload'].decode())
print("Document proof payload:")
print(json.dumps(payload, indent=2))
print("Document proof signature:")
print(document_proof.objects['signature'].hex())
print("----------------------------------")
# Change the authentication key
authentication_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key2',
        'type': "JsonWebKey2020",
        'publicKeyJwk': authentication_jwk.export_public(as_dict=True)
    }]
}

owner_registry.update(did_document)
#-------------Dumping-------------------
document, proofs = owner_registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
document_proof = jws.JWS()
document_proof.deserialize(proofs[0])
payload = json.loads(document_proof.objects['payload'].decode())
print("Document proof payload:")
print(json.dumps(payload, indent=2))
print("Document proof signature:")
print(document_proof.objects['signature'].hex())
print("----------------------------------")

# Delegate to a controller
controller_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
controller_public_key = controller_jwk.export_public(as_dict=True)
delegation = owner_registry.delegate(controller_public_key)
#-------------Dumping-------------------
delegation_proof = jws.JWS()
delegation_proof.deserialize(delegation)
payload = json.loads(delegation_proof.objects['payload'].decode())
print("Delegation proof payload:")
print(json.dumps(payload, indent=2))
print("Delegation proof signature:")
print(delegation_proof.objects['signature'].hex())
print("----------------------------------")

# Change the authentication key
# first configure controller registry
controller_registry = registry.DIDSelfRegistry(controller_jwk, delegation)
authentication_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key4',
        'type': "JsonWebKey2020",
        'publicKeyJwk': authentication_jwk.export_public(as_dict=True)
    }]
}

controller_registry.update(did_document)
#-------------Dumping-------------------
document, proofs = owner_registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
document_proof = jws.JWS()
document_proof.deserialize(proofs[0])
payload = json.loads(document_proof.objects['payload'].decode())
print("Document proof payload:")
print(json.dumps(payload, indent=2))
print("Document proof signature:")
print(document_proof.objects['signature'].hex())
print("----------------------------------")
print (owner_registry.verify(document, proofs))
