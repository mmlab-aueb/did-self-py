#from didself.proof_chain import  verify_proof_chain, verify_proof, generate_document_proof, generate_delegation_proof, get_controller
from didself.proof_chain import *

class DIDSelfRegistry:

    def __init__(self, user_jwk:'jws.JWK', delegetation_proof:'jws.JWS'=None):
        self._did = ""
        self._did_document = {}
        self._proof_chain = list()
        self._user_jwk = user_jwk
        self._is_delegated = False
        if (delegetation_proof):
            self._is_delegated = True
            self._did = get_id(delegetation_proof)
            self._proof_chain = [delegetation_proof] #fixxxx
             

    def create(self, did_document:list, created:str=None):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = generate_document_proof(did_document, self._user_jwk, created)
        proof_chain = [proof.serialize(compact=True)]   
        self.load(did_document, proof_chain)
    
    def read(self):
        return self._did_document, self._proof_chain
    
    def update(self, did_document):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation")
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        if (did_document["id"] != self._did):
             raise Exception("The DID document does not contain a valid id")
        proof = generate_document_proof(did_document, self._user_jwk)
        self._did_document = did_document
        if (self._is_delegated):
            if (len(self._proof_chain) == 1):
                self._proof_chain.append(proof.serialize(compact=True))
            else:
                self._proof_chain[1] = proof.serialize(compact=True)   
        else:
            self._proof_chain = [proof.serialize(compact=True)]

    def delegate(self, controller_jwk:dict, created:str=None):
        if (not self._user_jwk and not self._did_document):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = generate_delegation_proof(self._did_document, self._user_jwk, controller_jwk, created)
        return proof.serialize(compact=True)
    
    def verify(self, did_document:list, proof_chain:list):
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        try:
            verify_proof_chain(did_document['id'], did_document, proof_chain)             
        except:
            raise Exception("Invalid proof")
        return True

    def load(self, did_document:list, proof_chain:list):      
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        try:
            verify_proof_chain(did_document['id'], did_document, proof_chain)             
        except:
            raise Exception("Invalid proof")
            return -1
        self._did_document = did_document
        self._proof_chain = proof_chain
        self._did = did_document['id']
        controller_jwk = get_controller(proof_chain)
        if (controller_jwk):
            self._is_delegated = True

    



   
        


