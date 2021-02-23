from jwcrypto import jwk, jws
import json

class DIDSelfRegistry:

    def __init__(self):
        self._did = ""
        self._did_document = {}
        self._proof_chain = list()
        self._last_signer = ""

    def create(self, did_document, proof):
        document_dict = json.loads(did_document)      
        try:
            self._verify_proof(did_document, proof)             
        except:
            raise Exception("Invalid proof")
            return -1
        self._did = document_dict['id']
        self._did_document = document_dict
        self._proof_chain.append(proof)
        self._last_signer =  self._did

    def update(self, did_document, proof):
        document_dict = json.loads(did_document)
        try:
            self._verify_proof(did_document, proof)             
        except:
            raise Exception("Invalid proof")
            return -1
        if (self._last_signer == self._did_document['controller']): 
            self._proof_chain[-1] = proof
        else:
            self._proof_chain.append(proof)
        self._last_signer =  self._did_document['controller']
        self._did_document = document_dict

    def read(self):
        return self._did_document, self._proof_chain
        
    def _verify_proof (self, did_document, proof):
        try:
            document_dict = json.loads(did_document)
        except:
            raise Exception("Not a valid DID document")
            return -1
        if ("controller" not in document_dict or "id" not in document_dict):
            raise Exception("The DID document does not contain id or controller")
            return -1
        if (not self._did_document): #checks for crete()
            if (document_dict['controller'] != document_dict['id']):
                raise Exception("The DID document does not contain a valid controller")
                return -1
        else: #check for update
            if (document_dict['id'] != self._did):
                raise Exception("The DID document does not contain a valid id")
                return -1

        # check if proof contains controller
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(proof)
        payload = json.loads(claimed_proof.objects['payload'].decode())
        controller = document_dict['controller']
        if (not self._did_document ): # invoked by the create method
            signer = controller
        else:
            signer = self._did_document['controller']
        try:
            signer_key_64 = signer.split(":")[2]
            signer_key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': signer_key_64}
            signer_jwk = jwk.JWK(**signer_key_dict)
        except:
            raise Exception("Not valid DID document controller")
            return -1
        # check if the controller is the current controller of the did_document
        # verify jws
        if ("id" not in payload or  "controller" not in payload):
            raise Exception("Not valid proof")
            return -1 
        if (payload['id'] != document_dict['id'] or  payload['controller'] != controller):
            raise Exception("Not valid proof")
            return -1
        claimed_proof.verify(signer_jwk)
        return True


