# A python implementation of did:self
This is a python implementation of the [did:self method](https://github.com/mmlab-aueb/did-self)

# Usage
This library can be used for Creating, Reading, Updating, or Delegating a 
did:self DID. This operations are supported by an auxiliary script called the
`self registry`.

## Self registry preparation
Before any operation, a did:self a self registry must be configured with the
user's key pair, encoded in JWK, and optionally with a `delegation proof` (see
the DID delegation section). An example of registry initialization is the following

```python
did_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
owner_registry = registry.DIDSelfRegistry(did_key)
```

## Create
A did:self DID is the base64url value of an Ed25519. In order to create a did:self
DID, a user must generate the corresponding key-pair, create a DID document, and
invoke the `create` method of the DID registry. An example of this process follows

```python
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
```
## Read
By invoking the `read` operation of the registry a user obtains the DID document, 
the `document proof`, and (if any) the `delegation proof`.

## Update
A DID document can be simply updated by invoking the `update` method of the
registry, providing as input the new DID document. For example:

```python
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
```
## Delegate
A did:self owner can delegate a DID to another entity. This is achieved by
invoking the `delegate` method of the registry, providing as input the public
key of that entity. The method outputs a `delegation proof`. Foe example:

```python
controller_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
controller_public_key = controller_jwk.export_public(as_dict=True)
delegation = owner_registry.delegate(controller_public_key)
```