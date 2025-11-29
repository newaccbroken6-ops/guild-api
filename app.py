import httpx
import time
import re
import os  # Add os import for environment variables
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify
from datetime import datetime
import asyncio
import data_pb2
import encode_id_clan_pb2

# ===================== CONFIG =====================
app = Flask(__name__)
freefire_version = "OB51"
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
jwt_tokens = {}  # Store tokens by region
# =================================================

# ===================== REGION CONFIG =====================
def get_region_credentials(region):
    r = region.upper()
    if r == "ME":  # Only ME server
        return "uid=4313063484&password=LINUX_8669R_BY_SPIDEERIO_GAMING_OIH7B"
    else:
        return "uid=4197713441&password=6478B1F1D3BC4CB0AC89079BA3297E29B3285BEEED3A87F7191B8AE277D6DD55"

# ===================== ENCRYPT UID =====================
def Encrypt_ID(x):
    x = int(x)
    dec = [f'{i:02x}' for i in range(128, 256)]
    xxx = [f'{i:02x}' for i in range(0, 128)]

    parts = []
    while x > 0:
        parts.append(x % 128)
        x //= 128
    while len(parts) < 5:
        parts.append(0)
    parts.reverse()

    return ''.join(dec[parts[i]] if i > 0 else xxx[parts[i]] for i in range(5))

# ===================== AES ENCRYPT =====================
def encrypt_api(plain_text_hex):
    plain_text = bytes.fromhex(plain_text_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, 16)).hex()

# ===================== EMOTE ID EN/DE =====================
def Encrypt_id_emote(uid):
    result = []
    while uid > 0:
        byte = uid & 0x7F
        uid >>= 7
        if uid > 0:
            byte |= 0x80
        result.append(byte)
    return bytes(result).hex()

def Decrypt_id_emote(uidd):
    bytes_value = bytes.fromhex(uidd)
    r, shift = 0, 0
    for byte in bytes_value:
        r |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return r

# ===================== TIMESTAMP =====================
def convert_timestamp(ts):
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

# ===================== JWT TOKEN =====================
async def get_jwt_token(region):
    global jwt_tokens
    credentials = get_region_credentials(region)
    
    # Use the new JWT API endpoint
    url = f"https://new-jwt-api.onrender.com/api/token?{credentials}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10)
            print(f"[DEBUG] JWT API Response Status: {response.status_code}")  # Debug log
            
            if response.status_code == 200:
                data = response.json()
                print(f"[DEBUG] JWT API Response Body: {data}")  # Debug log
                
                # Check if we got a token directly (new format)
                if 'token' in data:
                    jwt_tokens[region.upper()] = data['token']
                    print(f"[+] JWT Token Updated for {region}: {data['token'][:50]}...")
                    return True
                # Check if we got the old format with status
                elif data.get('status') == 'success':
                    jwt_tokens[region.upper()] = data['token']
                    print(f"[+] JWT Token Updated for {region}: {data['token'][:50]}...")
                    return True
                else:
                    print(f"[-] JWT API Error for {region}: {data}")  # Log error response
                    # Even if there's an error, if we have a token, we'll use it
                    if 'token' in data:
                        jwt_tokens[region.upper()] = data['token']
                        print(f"[+] JWT Token Updated for {region}: {data['token'][:50]}...")
                        return True
            else:
                print(f"[-] JWT API HTTP Error for {region}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[-] JWT Token Error for {region}: {e}")
    return False

async def token_updater():
    regions = ["ME"]  # Only ME server
    while True:
        for region in regions:
            await get_jwt_token(region)
            await asyncio.sleep(10)  # Small delay between regions
        await asyncio.sleep(8 * 3600)  # 8 hours

# ===================== CLAN INFO ROUTE (SYNC) =====================
@app.route('/info', methods=['GET'])
def get_clan_info():
    global jwt_tokens
    
    clan_id = request.args.get('clan_id')
    region = request.args.get('region', 'ME').upper()  # Only ME server
    
    # Only allow ME server
    if region != 'ME':
        return jsonify({"error": "This API is exclusive to ME server"}), 403
    
    if not clan_id:
        return jsonify({"error": "clan_id is required"}), 400

    # Check if token is ready
    if region not in jwt_tokens or not jwt_tokens[region]:
        # Try to get token one more time
        import asyncio
        try:
            # This is a hack to run async code in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(get_jwt_token(region))
            loop.close()
        except:
            pass
        
        # Check again
        if region not in jwt_tokens or not jwt_tokens[region]:
            return jsonify({"error": f"JWT token for region {region} not ready. Try again in a few seconds."}), 503

    try:
        # Prepare Protobuf
        json_data = json.dumps({"1": int(clan_id), "2": 1})
        my_data = encode_id_clan_pb2.MyData()
        json_obj = json.loads(json_data)
        my_data.field1 = json_obj["1"]
        my_data.field2 = json_obj["2"]

        data_bytes = my_data.SerializeToString()
        encrypted_data = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data_bytes, 16))
        data_hex = encrypted_data.hex()

        # Only ME server endpoint
        server_url = "https://clientbp.ggpolarbear.com"  # Working URL
        host = "clientbp.ggpolarbear.com"
        
        # Try to get server_url from JWT token if available
        if region in jwt_tokens and jwt_tokens[region]:
            try:
                import base64
                import json as json_lib  # Rename to avoid conflict
                # Decode JWT token to get server_url
                token_parts = jwt_tokens[region].split('.')
                if len(token_parts) > 1:
                    # Decode the payload (second part)
                    payload = token_parts[1]
                    # Add padding if needed
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += '=' * padding
                    decoded_payload = base64.urlsafe_b64decode(payload)
                    payload_data = json_lib.loads(decoded_payload)
                    if 'server_url' in payload_data:
                        server_url = payload_data['server_url']
                        host = server_url.replace("https://", "")
            except Exception as e:
                print(f"[DEBUG] Error extracting server_url from token: {e}")  # Debug log
                pass
        
        url = f"{server_url}/GetClanInfoByClanID"

        # Request headers
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt_tokens[region]}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": freefire_version,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Host": host,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        print(f"[DEBUG] Making request to: {url}")  # Debug log
        print(f"[DEBUG] Host header: {host}")  # Debug log

        # Synchronous HTTP using httpx
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_data)

        print(f"[DEBUG] FreeFire API Response Status: {response.status_code}")  # Debug log
        print(f"[DEBUG] FreeFire API Response Headers: {response.headers}")  # Debug log
        print(f"[DEBUG] FreeFire API Response Body Length: {len(response.content)}")  # Debug log

        if response.status_code != 200:
            return jsonify({"error": f"HTTP {response.status_code}", "body": response.text[:200]}), 500

        # Decrypt & Parse Response
        resp = data_pb2.response()
        resp.ParseFromString(response.content)

        print(f"[DEBUG] Parsed Response: {resp}")  # Debug log

        def ts(x): 
            if x > 0:
                return datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")
            else:
                return "N/A"

        # Extract guild details safely
        guild_details = getattr(resp, 'guild_details', None)
        
        # Create response with only the requested data
        result = {
            "clan_name": getattr(resp, 'special_code', ''),
            "created_at": ts(getattr(resp, 'timestamp1', 0)),
            "last_active": ts(getattr(resp, 'last_active', 0)),
            "level": getattr(resp, 'level', 0),
            "energy": getattr(resp, 'energy', 0),
            "value_a": getattr(resp, 'value_a', 0),
            "total_members": 0,  # This will remain 0 as the server doesn't provide it
            "members_online": 0,  # This will remain 0 as the server doesn't provide it
            "status": "success"
        }
        
        # Add guild details if available (though they seem to be empty)
        if guild_details:
            result.update({
                "members_online": getattr(guild_details, 'members_online', 0),
                "total_members": getattr(guild_details, 'total_members', 0)
            })

        return jsonify(result)

    except Exception as e:
        print(f"[DEBUG] Exception in get_clan_info: {e}")  # Debug log
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Server error", "details": str(e)}), 500

# ===================== HEALTH CHECK =====================
@app.route('/health', methods=['GET'])
def health_check():
    regions_status = {}
    for region in ["ME"]:  # Only ME server
        regions_status[region] = "ready" if region in jwt_tokens and jwt_tokens[region] else "not ready"
    
    return jsonify({
        "status": "running",
        "regions": regions_status,
        "timestamp": datetime.now().isoformat()
    })

# ===================== STARTUP =====================
def start_background_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(token_updater())
    loop.run_forever()

async def startup():
    # Start the background loop for token updates
    threading.Thread(target=start_background_loop, daemon=True).start()
    
    # Give it a moment to initialize
    await asyncio.sleep(1)

if __name__ == '__main__':
    import sys
    # Use PORT environment variable for Render, default to 5000 for local development
    port = int(os.environ.get('PORT', 5000))
    print(f"[🚀] Starting JWT-API on port {port} ...")
    
    try:
        asyncio.run(startup())
    except Exception as e:
        print(f"[⚠️] Startup warning: {e} — continuing without full initialization")
    
    app.run(host='0.0.0.0', port=port, debug=False)
    
