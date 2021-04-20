from didself.proof_chain import  verify_proof_chain, verify_proof, generate_proof, get_controller

class DIDSelfRegistry:

    def __init__(self, user_jwk:'jws.JWK'=None):
        self._did = ""
        self._did_document = {}
        self._proof_chain = list()
        self._controller_jwk = user_jwk
        self._has_controller = False
        self.set_key(user_jwk)

    def set_key(self, user_jwk:'jws.JWK'=None):
        self._user_jwk = user_jwk

    def create(self, did_document:list, controller_jwk:'jwk.JWK'=None, created:str=None):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = generate_proof(did_document, self._user_jwk, controller_jwk, created)
        proof_chain = [proof.serialize(compact=True)]   
        self.load(did_document, proof_chain)
    
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
            self._controller_jwk = controller_jwk
            self._has_controller = True

    def update(self, did_document):
        if (not self._user_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation")
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")
        if (did_document["id"] != self._did):
             raise Exception("The DID document does not contain a valid id")
        user_key_dict = self._user_jwk.export_public(as_dict=True)
        controller_key_dict = self._controller_jwk.export_public(as_dict=True)
        if (user_key_dict != controller_key_dict):
            raise Exception("The registry is configured with a key that cannot be used for updating the DID document")
            return -1
        proof = generate_proof(did_document, self._user_jwk)
        self._did_document = did_document
        if (self._has_controller):
            if (len(self._proof_chain) == 1):
                self._proof_chain.append(proof.serialize(compact=True))
            else:
                self._proof_chain[1] = proof.serialize(compact=True)    
        else:
            self._proof_chain = [proof.serialize(compact=True)]



    def read(self):
        return self._did_document, self._proof_chain
        


