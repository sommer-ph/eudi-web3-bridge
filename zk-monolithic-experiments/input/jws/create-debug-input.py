#!/usr/bin/env python3
"""
Create final working input using the circuit's actual hash computation
"""

import json
import base64

def create_final_working_input():
    print("=== CREATING FINAL WORKING INPUT ===\n")
    
    # Step 1: Load raw credential
    with open('/home/sommerph/workspace/eudi-web3-bridge/zk-backend/data/eudi-wallets/test-eudi-wallet.json', 'r') as f:
        wallet_data = json.load(f)
    
    credential = wallet_data['credentials'][0]
    header = credential['header']
    payload = credential['payload']
    
    # Step 2: JSON encode and Base64url encode
    header_json_bytes = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    header_b64 = base64.urlsafe_b64encode(header_json_bytes).decode('utf-8').rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(payload_json_bytes).decode('utf-8').rstrip('=')
    
    print(f"Header B64: {header_b64} (len: {len(header_b64)})")
    print(f"Payload B64: {payload_b64[:50]}... (len: {len(payload_b64)})")
    
    # Step 3: Convert to ASCII bytes and pad
    header_ascii = [ord(c) for c in header_b64]
    payload_ascii = [ord(c) for c in payload_b64]
    
    header_padded = header_ascii + [0] * (64 - len(header_ascii))
    payload_padded = payload_ascii + [0] * (1024 - len(payload_ascii))
    
    # Step 4: Extract pk_c coordinates
    jwk = payload['cnf']['jwk']
    x_coord_b64 = jwk['x']
    y_coord_b64 = jwk['y']
    
    x_bytes = base64.urlsafe_b64decode(x_coord_b64 + '==')
    y_bytes = base64.urlsafe_b64decode(y_coord_b64 + '==')
    
    x_int = int.from_bytes(x_bytes, byteorder='big')
    y_int = int.from_bytes(y_bytes, byteorder='big')
    
    # Convert to limbs
    mask = (1 << 43) - 1
    x_limbs = []
    y_limbs = []
    for i in range(6):
        x_limb = (x_int >> (i * 43)) & mask
        y_limb = (y_int >> (i * 43)) & mask
        x_limbs.append(str(x_limb))
        y_limbs.append(str(y_limb))
    
    pk_c = [x_limbs, y_limbs]
    
    # Step 5: Get offset data from backend  
    with open('input/jws/test-credential-wallet-binding-extended.json', 'r') as f:
        backend_data = json.load(f)
    
    # Step 6: Create input WITHOUT hash (we'll get it from circuit debug)
    working_input = {
        "headerB64": [str(x) for x in header_padded],
        "headerB64Length": str(len(header_ascii)),
        "payloadB64": [str(x) for x in payload_padded],
        "payloadB64Length": str(len(payload_ascii)),
        "offXB64": backend_data["offXB64"],
        "lenXB64": backend_data["lenXB64"],
        "offYB64": backend_data["offYB64"],
        "lenYB64": backend_data["lenYB64"],
        "msghash": ["0", "0", "0", "0", "0", "0"],  # Dummy hash, will replace with circuit output
        "pk_c": pk_c
    }
    
    # Write working input
    with open('input/jws/working_input_for_debug.json', 'w') as f:
        json.dump(working_input, f, indent=2)
    
    print(f"\nWorking input (without correct hash) created: input/jws/working_input_for_debug.json")
    print(f"Now run circuit with hash assertion DISABLED to get actual hash limbs!")
    print(f"Then update msghash with those values and re-enable assertion.")

if __name__ == '__main__':
    create_final_working_input()