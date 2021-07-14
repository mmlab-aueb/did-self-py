from didself.proof_chain import *

def verify(did_document:dict, document_proof:str, delegation_proof:str=None):
        if ("id" not in did_document):
            print("The DID document does not contain id")
            return False
        try:
            verify_document(did_document['id'], did_document, document_proof, delegation_proof)           
        except:
            return False
        return True

class DIDSelfRegistry:
    def __init__(self, user_jwk:'jws.JWK', delegetation_proof:str=None):
        self._did = ""
        self._delegation_proof = ""
        self._document_proof = ""
        self._did_document = {}
        self._user_jwk = user_jwk
        if (delegetation_proof):
            self._did = get_id(delegetation_proof)
            self._delegation_proof = delegetation_proof
             

    def create(self, did_document:list, created:str=None):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = generate_document_proof(did_document, self._user_jwk, created)
        self.load(did_document, proof.serialize(compact=True))
    
    def read(self):
        return self._did_document, self._document_proof, self._delegation_proof
    
    def update(self, did_document):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation")
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        if (did_document["id"] != self._did):
             raise Exception("The DID document does not contain a valid id")
        proof = generate_document_proof(did_document, self._user_jwk)
        self._did_document = did_document
        self._document_proof = proof.serialize(compact=True)

    def delegate(self, controller_jwk:dict, created:str=None):
        if (not self._user_jwk and not self._did_document):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = generate_delegation_proof(self._did_document, self._user_jwk, controller_jwk, created)
        return proof.serialize(compact=True)

    def load(self, did_document:list, document_proof:str, delegation_proof:str=None):      
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        try:
            verify_document(did_document['id'], did_document, document_proof, delegation_proof)             
        except:
            raise Exception("Invalid proof")
            return -1
        self._did_document = did_document
        self._document_proof = document_proof
        self.delegation_proof = delegation_proof
        self._did = did_document['id']
    
    
 

    



   
        


