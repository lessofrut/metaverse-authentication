from flask import Flask, request, jsonify
from vc_verifier import VCVerifier
import json
import os

app = Flask(__name__)
verifier = VCVerifier()

@app.route('/verify-vp', methods=['POST'])
def verify_vp():
    """
    Endpoint to verify a Verifiable Presentation
    Expects: { "vp": {...} }
    The VP contains the VC inside it.
    """
    try:
        data = request.get_json()

        if not data or 'vp' not in data:
            return jsonify({"success": False, "error": "Missing VP in request"}), 400
        
        vp = data['vp'] 

        # Verify the presentation and its credential
        result = verifier.verify_presentation(vp)
        
        return jsonify(result), 200 if result['success'] else 400
        
    except Exception as e:
        return jsonify({ 
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    # Run on localhost, port 5000
    app.run(debug=True, host='0.0.0.0', port=5000)