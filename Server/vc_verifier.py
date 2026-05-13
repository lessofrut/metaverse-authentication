import json
import hashlib
import hmac
from datetime import datetime
from pathlib import Path

class VCVerifier:
    """
    Verifies Verifiable Presentations and their contained Verifiable Credentials locally.
    
    Validation flow:
    1. Extract VC from VP
    2. Verify VP signature using Holder's DID
    3. Verify VC signature using Issuer's DID
    4. Validate Issuer DID matches
    5. Validate Holder DID matches VP holder
    6. Check credential expiration
    """

    def __init__(self, credentials_path="sample_credentials"):
        self.credentials_path = Path(credentials_path)
        self.credentials_path.mkdir(exist_ok=True)
        self._load_dids()

    def _load_dids(self):
        """Load DID documents from local files"""
        self.issuer_did = self._load_json("issuer_did.json")
        self.holder_did = self._load_json("holder_did.json")

        if not self.issuer_did:
            print("Warning: issuer_did.json not found")
        if not self.holder_did:
            print("Warning: holder_did.json not found")
            
            
    def _load_json(self, filename):
        """Load JSON file from credentials directory"""
        filepath = self.credentials_path / filename
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
        return None

    def verify_presentation(self, vp):
        """
        Main verification method for a Verifiable Presentation
        
        Args:
            vp (dict): Verifiable Presentation containing a VC
        
        Returns:
            dict: Verification result with details
        """
        result = {
            "success": False,
            "checks": {},
            "details": "",
            "vp_data": {}
        }

        try:
             # Check 1: Validate VP structure
            structure_valid = self._validate_vp_structure(vp)
            result["checks"]["vp_structure_valid"] = structure_valid
            if not structure_valid:
                result["details"] = "Invalid VP structure"
                return result

            # Extract VC from VP
            vc = self._extract_vc_from_vp(vp)
            if not vc:
                result["details"] = "No VC found in VP"
                return result

            # Check 2: Validate VC structure
            vc_structure_valid = self._validate_vc_structure(vc)
            result["checks"]["vc_structure_valid"] = vc_structure_valid
            if not vc_structure_valid:
                result["details"] = "Invalid VC structure"
                return result

            # Check 3: Verify VP signature (Holder's signature)
            vp_sig_valid = self._verify_vp_signature(vp)
            result["checks"]["vp_signature_valid"] = vp_sig_valid
            if not vp_sig_valid:
                result["details"] = "VP signature verification failed"
                return result

            # Check 4: Verify VC signature (Issuer's signature)
            vc_sig_valid = self._verify_vc_signature(vc)
            result["checks"]["vc_signature_valid"] = vc_sig_valid
            if not vc_sig_valid:
                result["details"] = "VC signature verification failed"
                return result

            # Check 5: Verify Issuer DID matches
            issuer_valid = self._verify_issuer(vc)
            result["checks"]["issuer_valid"] = issuer_valid
            if not issuer_valid:
                result["details"] = "Issuer DID does not match"
                return result

            # Check 6: Verify Holder DID matches VP holder
            holder_valid = self._verify_holder(vp, vc)
            result["checks"]["holder_valid"] = holder_valid
            if not holder_valid:
                result["details"] = "Holder DID does not match VP holder"
                return result

            # Check 7: Verify credential expiration
            expiry_valid = self._check_expiration(vc)
            result["checks"]["not_expired"] = expiry_valid
            if not expiry_valid:
                result["details"] = "Credential has expired"
                return result
            
             # All checks passed
            result["success"] = True
            result["details"] = "All verification checks passed"
            result["vp_data"] = {
                "holder": vp.get("holder"),
                "issuer": vc.get("issuer"),
                "credential_subject": vc.get("credentialSubject", {}),
                "issued_at": vc.get("issuanceDate"),
                "expires_at": vc.get("expirationDate"),
                "credential_type": vc.get("type", [])
            }

        except Exception as e:
            result["details"] = f"Verification error: {str(e)}"
            import traceback
            traceback.print_exc()

        return result

    def _validate_vp_structure(self, vp):
        """Check if VP has required fields"""
        required_fields = ["@context", "type", "verifiableCredential", "holder", "proof"]
        return all(field in vp for field in required_fields)

    def _validate_vc_structure(self, vc):
        """Check if VC has required fields"""
        required_fields = ["@context", "type", "issuer", "credentialSubject", "issuanceDate", "proof"]
        return all(field in vc for field in required_fields)
    
    def _validate_vc_structure(self, vc):
        """Check if VC has required fields"""
        required_fields = ["@context", "type", "issuer", "credentialSubject", "issuanceDate", "proof"]
        return all(field in vc for field in required_fields)

    def _extract_vc_from_vp(self, vp):
        """Extract the VC from the VP"""
        try:
            credentials = vp.get("verifiableCredential", [])
            if isinstance(credentials, list) and len(credentials) > 0:
                return credentials[0]
            return None
        except Exception:
            return None

    def _verify_vp_signature(self, vp):
        """
        Verify the VP signature using the Holder's public key
        
        The signature is computed over the VP without the proof field
        """
        try:
            if not self.holder_did:
                print("Error: Holder DID not loaded")
                return False

            proof = vp.get("proof", {})
            signature = proof.get("signatureValue")

            # Get holder's public key
            public_key = self._extract_public_key(self.holder_did)

            if not signature or not public_key:
                print(f"Error: Missing signature or public key. Sig: {signature}, Key: {public_key}")
                return False

            # Create a signature message from VP (excluding proof)
            vp_copy = {k: v for k, v in vp.items() if k != "proof"}
            message = json.dumps(vp_copy, separators=(',', ':'), ensure_ascii=False)

            # Verify HMAC-SHA256 signature
            expected_signature = self._compute_hmac_signature(public_key, message)

            match = signature == expected_signature
            if not match:
                print(f"VP signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return match

        except Exception as e:
            print(f"VP signature verification error: {str(e)}")
            return False

    def _verify_vc_signature(self, vc):
        """
        Verify the VC signature using the Issuer's public key
        
        The signature is computed over the VC without the proof field
        """
        try:
            if not self.issuer_did:
                print("Error: Issuer DID not loaded")
                return False

            proof = vc.get("proof", {})
            signature = proof.get("signatureValue")

            # Get issuer's public key
            public_key = self._extract_public_key(self.issuer_did)

            if not signature or not public_key:
                print(f"Error: Missing signature or public key. Sig: {signature}, Key: {public_key}")
                return False

            # Create a signature message from VC (excluding proof)
            vc_copy = {k: v for k, v in vc.items() if k != "proof"}
            message = json.dumps(vc_copy, separators=(',', ':'), ensure_ascii=False)

            # Verify HMAC-SHA256 signature
            expected_signature = self._compute_hmac_signature(public_key, message)

            match = signature == expected_signature
            if not match:
                print(f"VC signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return match

        except Exception as e:
             print(f"VC signature verification error: {str(e)}")
        return False

    def _compute_hmac_signature(self, public_key, message):
        """Compute HMAC-SHA256 signature"""
        return hmac.new(
            public_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    def _extract_public_key(self, did_document):
        """Extract public key from DID document"""
        public_key_list = did_document.get("publicKey", [])
        if len(public_key_list) > 0:
            return public_key_list[0].get("publicKeyPem", "")
        return None

    def _verify_issuer(self, vc):
        """Verify that the issuer DID matches the stored issuer"""
        if not self.issuer_did:
            return False

        issuer = vc.get("issuer")
        stored_issuer = self.issuer_did.get("id")

        match = issuer == stored_issuer
        if not match:
            print(f"Issuer mismatch. VC Issuer: {issuer}, Stored: {stored_issuer}")
        return match

    def _verify_holder(self, vp, vc):
        """
        Verify that:
        1. The VP holder matches stored holder DID
        2. The VC subject matches stored holder DID
        3. The VP holder matches VC subject
        """
        if not self.holder_did:
            return False

        vp_holder = vp.get("holder")
        stored_holder = self.holder_did.get("id")
        vc_subject = vc.get("credentialSubject", {}).get("id")

        holder_match = vp_holder == stored_holder
        subject_match = vc_subject == stored_holder
        holder_subject_match = vp_holder == vc_subject

        if not holder_match:
            print(f"VP holder mismatch. VP: {vp_holder}, Stored: {stored_holder}")
        if not subject_match:
            print(f"VC subject mismatch. Subject: {vc_subject}, Stored: {stored_holder}")
        if not holder_subject_match:
            print(f"VP holder doesn't match VC subject. VP: {vp_holder}, Subject: {vc_subject}")

        return holder_match and subject_match and holder_subject_match

    def _check_expiration(self, vc):
        """Check if credential has expired"""
        expiration_date = vc.get("expirationDate")

        if not expiration_date:
             return True  # No expiration means valid

        try:
            exp_datetime = datetime.fromisoformat(expiration_date.replace('Z', '+00:00'))
            now = datetime.now(exp_datetime.tzinfo)
            expired = now >= exp_datetime
            if expired:
                print(f"Credential expired at {expiration_date}")
            return not expired
        except Exception as e:
            print(f"Error checking expiration: {str(e)}")
            return False