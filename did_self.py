from jwcrypto import jwk, jws
import json

class DID_Self:

    def __init__(self):
        self._did = ""
        self._did_document = {}
        self._document_proof = list()

    def create(self, did, did_document, proof):
        # check if did document includes a valid controller
        try:
            document_dict = json.loads(did_document)
        except:
            raise Exception("Not a valid DID document")
            return -1
        if ("controller" not in document_dict and document_dict['controller'] != did):
            raise Exception("The DID document does not contain a controller")
            return -1
        # verify proof
        controller = document_dict['controller']
        try:
            controller_key_64 = controller.split(":")[2]
            controller_key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': controller_key_64}
            controller_jwk = jwk.JWK(**controller_key_dict)
        except:
            raise Exception("Not valid DID document controller")
            return -1
        try:
            claimed_proof = jws.JWS()
            claimed_proof.deserialize(proof)
            payload = json.loads(claimed_proof.objects['payload'].decode())

            if ("did" not in payload or  "controller" not in payload):
                raise Exception("Not valid proof")
                return -1 
            if (payload['did'] != did or  payload['controller'] != controller):
                raise Exception("Not valid proof")
                return -1  

            claimed_proof.verify(controller_jwk) 
            print(claimed_proof.objects)
        except:
            raise Exception("Invalid proof")
            return -1
        self._did = did
        self._did_document = did_document
        self._document_proof.append(proof)

    def update(self, did_document, proof):
        # check if did cocuemnt includes controller
        # verify proof

        self._did_document = did_document

    def _verify_proof (did_document, proof):
        # check if proof contains controller
        # check if the controller is the current controller of the did_document
        # verify jws

        return True


