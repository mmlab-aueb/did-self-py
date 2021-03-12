from didself.proof_chain import  verify_proof_chain, verify_proof

class DIDSelfRegistry:

    def __init__(self):
        self._did = ""
        self._did_document = {}
        self._proof_chain = list()
        self._last_signer = ""

    def create(self, did_document:list, proof:'jws.JWS'):
        proof_chain = [proof.serialize(compact=True)]
        self.load(did_document, proof_chain)
    
    def load(self, did_document:list, proof_chain:list):      
        if ("controller" not in did_document or "id" not in did_document):
            raise Exception("The DID document does not contain id or controller")
        try:
            verify_proof_chain(did_document['id'], did_document, proof_chain)             
        except:
            raise Exception("Invalid proof")
            return -1
        self._did_document = did_document
        self._proof_chain = proof_chain
        self._last_signer =  did_document['id']
        self._did = did_document['id']


    def update(self, did_document, proof):
        if ("controller" not in did_document or "id" not in did_document):
            raise Exception("The DID document does not contain id or controller")
        if (did_document["id"] != self._did):
             raise Exception("The DID document does not contain a valid id")
        try:
            signer = self._did_document['controller']
            verify_proof(did_document, proof, signer)             
        except:
            raise Exception("Invalid proof")
            return -1
        if (self._last_signer == signer): 
            self._proof_chain[-1] = proof.serialize(compact=True)
        else:
            self._proof_chain.append(proof.serialize(compact=True))
        self._last_signer =  signer
        self._did_document = did_document

    def read(self):
        return self._did_document, self._proof_chain
        


