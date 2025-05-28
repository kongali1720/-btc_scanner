import requests
import secrets
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def generate_btc_wallet():
    private_key = secrets.token_hex(32)
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x04' + vk.to_string()
    
    sha256 = hashlib.sha256(pubkey).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    network_byte = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum).decode()

    return private_key, address

def check_balance(address):
    url = f"https://blockstream.info/api/address/{address}"
    try:
        response = requests.get(url)
        data = response.json()
        return data['chain_stats']['funded_txo_sum'] / 1e8
    except:
        return "Error fetching balance"

if __name__ == "__main__":
    priv, addr = generate_btc_wallet()
    print(f"🔐 Private Key: {priv}")
    print(f"🏦 BTC Address: {addr}")
    balance = check_balance(addr)
    print(f"💰 Balance: {balance} BTC")
