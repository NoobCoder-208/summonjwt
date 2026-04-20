import json
import base64
import asyncio
import httpx
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
import logging
from google.protobuf import json_format
import sys

# Configure logging for Vercel
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Attempt to import Protobuf
try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    logger.info("Successfully imported Protobuf modules")
except ImportError as e:
    logger.error(f"Failed to import Protobuf modules: {e}")
    raise ImportError("Ensure Protobuf files are in the proto/ directory.")

# === Settings ===
try:
    MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
    MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
    logger.info("Successfully decoded MAIN_KEY and MAIN_IV")
except Exception as e:
    logger.error(f"Failed to decode MAIN_KEY or MAIN_IV: {e}")
    raise
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB53"

app = Flask(__name__)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    try:
        padding_length = AES.block_size - (len(text) % AES.block_size)
        return text + bytes([padding_length] * padding_length)
    except Exception as e:
        logger.error(f"Padding failed: {e}")
        raise

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    try:
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.encrypt(pad(plaintext))
    except Exception as e:
        logger.error(f"AES encryption failed: {e}")
        raise

async def json_to_proto(json_data: str, proto_message) -> bytes:
    try:
        json_format.ParseDict(json.loads(json_data), proto_message)
        return proto_message.SerializeToString()
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Protobuf conversion failed: {e}")
        raise

def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        # Add padding if necessary
        missing_padding = len(payload_b64) % 4
        if missing_padding:
            payload_b64 += '=' * (4 - missing_padding)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        return json.loads(payload_json)
    except Exception as e:
        logger.error(f"Failed to decode JWT payload: {e}")
        return {}

def encode_varint(value):
    """Encodes an integer as a protobuf varint."""
    if value == 0:
        return b'\x00'
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value & 0x7f)
    return bytes(out)

async def get_player_info(account_id: int, token: str, server_url: str):
    try:
        # Construct protobuf payload manually for GetPlayerPersonalShow
        # Field 1: a (AccountID) - type: int64
        # Field 2: b (7) - type: int32
        proto_bytes = b'\x08' + encode_varint(account_id) + b'\x10\x07'
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        
        url = f"{server_url}/GetPlayerPersonalShow"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': f"Bearer {token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=payload, headers=headers)
            if resp.status_code != 200:
                logger.error(f"GetPlayerPersonalShow failed with status {resp.status_code}: {resp.text}")
                return 0, "Unknown"
                
            res_msg = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            res_msg.ParseFromString(resp.content)
            res_dict = json_format.MessageToDict(res_msg, preserving_proto_field_name=True)
            
            basic_info = res_dict.get('basic_info', {})
            level = int(basic_info.get('level', 0))
            nickname = basic_info.get('nickname', 'Unknown')
            return level, nickname
    except Exception as e:
        logger.error(f"Failed to get player info: {e}")
        return 0, "Unknown"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Sending access token request to {url}")
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")
            return access_token, open_id
    except Exception as e:
        logger.error(f"Failed to get access token: {e}")
        raise

async def create_jwt(uid: str, password: str):
    try:
        account = f"uid={uid}&password={password}"
        logger.info(f"Generating JWT for uid: {uid}")
        token_val, open_id = await get_access_token(account)
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggwhitehawk.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2022.3.47f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        async with httpx.AsyncClient() as client:
            logger.info(f"Sending JWT request to {url}")
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            msg = json.loads(json_format.MessageToJson(FreeFire_pb2.LoginRes.FromString(resp.content)))
            token = msg.get('token', '0')
            server_url = msg.get('serverUrl', '0')
            
            if token == '0':
                return {
                    'token': '0',
                    'access_token': token_val,
                    'level': 0,
                    'name': 'Unknown',
                    'region': msg.get('lockRegion', '0'),
                    'server_url': server_url
                }
            
            # Decode JWT to get internal account_id
            payload_data = decode_jwt_payload(token)
            account_id = payload_data.get('account_id', 0)
            
            # Get player info (level, name) using internal account_id
            level, nickname = await get_player_info(int(account_id), token, server_url)
            
            return {
                'token': f"{token}",
                'access_token': token_val,
                'level': level,
                'name': nickname,
                'region': msg.get('lockRegion', '0'),
                'server_url': server_url
            }
    except Exception as e:
        logger.error(f"JWT creation failed: {e}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "API is running", "version": RELEASEVERSION}), 200

@app.route('/token', methods=['GET'])
def get_jwt():
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        if not uid or not password:
            return jsonify({"error": "Please provide both uid and password."}), 400
        result = asyncio.run(create_jwt(uid, password))
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in get_jwt: {e}")
        return jsonify({"error": f"Failed: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5600
    app.run(host='0.0.0.0', port=port, debug=False)
