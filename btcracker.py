import hashlib
import secrets
import binascii
import requests
import time
import random
from typing import Tuple

# ----------------------------
# Bitcoin Utilities
# ----------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58_encode(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    return encoded

def private_key_to_wif(private_key_hex: str, compressed: bool = True) -> str:
    extended_key = '80' + private_key_hex
    if compressed:
        extended_key += '01'
    extended_bytes = bytes.fromhex(extended_key)
    checksum = sha256(extended_bytes)[:4]
    wif_bytes = extended_bytes + checksum
    return base58_encode(wif_bytes)

def private_key_to_public_key(private_key_hex: str, compressed: bool = True) -> str:
    try:
        from ecdsa import SigningKey, SECP256k1
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        if compressed:
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            prefix = '02' if (y % 2 == 0) else '03'
            return prefix + format(x, '064x')
        else:
            return '04' + format(vk.pubkey.point.x(), '064x') + format(vk.pubkey.point.y(), '064x')
    except ImportError:
        print("Install ecdsa: pip install ecdsa")
        return "04" + "0" * 128

def public_key_to_address(public_key_hex: str) -> str:
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()
    extended_hash = b'\x00' + hashed_public_key
    checksum = sha256(extended_hash)[:4]
    address_bytes = extended_hash + checksum
    return base58_encode(address_bytes)

def generate_bitcoin_keypair(compressed: bool = True) -> Tuple[str, str, str]:
    private_key_bytes = secrets.token_bytes(32)
    private_key_hex = binascii.hexlify(private_key_bytes).decode()
    wif = private_key_to_wif(private_key_hex, compressed)
    public_key = private_key_to_public_key(private_key_hex, compressed)
    address = public_key_to_address(public_key)
    return private_key_hex, wif, address

# ----------------------------
# Balance Checkers
# ----------------------------

APIS = [
    {
        'name': 'Blockstream',
        'url': 'https://blockstream.info/api/address/{}',
        'parse': lambda data: (data.get('chain_stats', {}).get('funded_txo_sum', 0) - 
                               data.get('chain_stats', {}).get('spent_txo_sum', 0) +
                               data.get('mempool_stats', {}).get('funded_txo_sum', 0) - 
                               data.get('mempool_stats', {}).get('spent_txo_sum', 0)) / 100000000
    },
    {
        'name': 'Mempool.space',
        'url': 'https://mempool.space/api/address/{}',
        'parse': lambda data: (data.get('chain_stats', {}).get('funded_txo_sum', 0) - 
                               data.get('chain_stats', {}).get('spent_txo_sum', 0) +
                               data.get('mempool_stats', {}).get('funded_txo_sum', 0) - 
                               data.get('mempool_stats', {}).get('spent_txo_sum', 0)) / 100000000
    },
    {
        'name': 'BlockCypher',
        'url': 'https://api.blockcypher.com/v1/btc/main/addrs/{}',
        'parse': lambda data: data.get('balance', 0) / 100000000
    },
    {
        'name': 'Chain.so',
        'url': 'https://chain.so/api/v2/get_address_balance/BTC/{}',
        'parse': lambda data: float(data.get('data', {}).get('confirmed_balance', '0'))
    },
]

def check_balance(address: str, api: dict) -> float:
    """Check balance using ONE specific API"""
    try:
        url = api['url'].format(address)
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            return api['parse'](data)
        return 0
    except:
        return 0

# ----------------------------
# Main
# ----------------------------

def main():
    print("=" * 60)
    print("BITCOIN KEY GENERATOR - RAPID CHECK")
    print("=" * 60)
    
    num_keys = int(input("How many keys to generate?: "))
    compressed = input("Use compressed addresses? (y/n, default y): ").lower() != 'n'
    
    print("\n" + "=" * 60)
    print(f"GENERATING {num_keys} KEYS...")
    print("=" * 60)
    
    total_balance = 0
    found = []
    start = time.time()
    
    for i in range(num_keys):
        # Generate
        pk, wif, addr = generate_bitcoin_keypair(compressed)
        
        # Pick random API
        api = random.choice(APIS)
        
        # Check balance
        balance = check_balance(addr, api)
        
        print(f"\n[{i+1}] {addr}")
        print(f"    Balance: {balance:.8f} BTC (via {api['name']})")
        print(f"    WIF: {wif}")
        
        if balance > 0:
            total_balance += balance
            found.append({'addr': addr, 'balance': balance, 'wif': wif, 'pk': pk})
    
    # Summary
    print("\n" + "=" * 60)
    print(f"TIME: {time.time()-start:.1f} sec")
    print(f"SPEED: {num_keys/(time.time()-start):.1f} keys/sec")
    
    if found:
        print(f"\n💰 FOUND {len(found)} ADDRESSES WITH BALANCE: {total_balance:.8f} BTC")
        for f in found:
            print(f"\n  {f['addr']}")
            print(f"  Balance: {f['balance']} BTC")
            print(f"  WIF: {f['wif']}")
            print(f"  Private Key: {f['pk']}")
    else:
        print("\n💀 No balances found")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
