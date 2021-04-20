from didself import registry
from jwcrypto import jwk, jws
import json

# DID creation
# Generate DID and initial secret key
did_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
# Initialize registry
registry = registry.DIDSelfRegistry(did_key)
did_key_dict = did_key.export_public(as_dict=True)
# Generate the DID document
did = "did:self:" + did_key_dict['x']
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}

registry.create(did_document)
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

registry.update(did_document)
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

#Create a DID document with a controller
controller_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key3',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}

registry.create(did_document, controller_jwk=controller_jwk)
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

# Change the authentication key
# first configure the registry to use the contoller key
registry.set_key(controller_jwk)
authentication_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'authentication': [{
        'id': did + '#key4',
        'type': "JsonWebKey2020",
        'publicKeyJwk': authentication_jwk.export_public(as_dict=True)
    }]
}

registry.update(did_document)
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
