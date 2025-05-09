import os
from flask import Flask, request, abort
from Crypto.Cipher import AES

app = Flask(__name__)
FLAG = open("flag.txt").read().strip()
# secret key for CBC-MAC
KEY = os.urandom(16)
IV = bytes(16)

# compute raw CBC without padding; data must be multiple of block size
def cbc_mac(data: bytes) -> bytes:
    if len(data) % AES.block_size != 0:
        abort(400, description="Data length must be multiple of 16 bytes (hex length %32 == 0)")
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(data)
    return ct[-AES.block_size:]

@app.route('/sign')
def sign():
    data_hex = request.args.get('data', '')
    try:
        data = bytes.fromhex(data_hex)
    except ValueError:
        abort(400, description='Invalid hex')
    mac = cbc_mac(data)
    return {'data': data_hex, 'mac': mac.hex()}

@app.route('/auth')
def auth():
    data_hex = request.args.get('data', '')
    sig = request.args.get('mac', '')
    try:
        data = bytes.fromhex(data_hex)
        mac = bytes.fromhex(sig)
    except ValueError:
        abort(400, description='Invalid hex')
    real = cbc_mac(data)
    if real != mac:
        abort(403)
    # check for admin flag
    if data.endswith(b';admin=true;'):
        return {'flag': FLAG}
    return {'status': 'ok', 'data': data_hex}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
