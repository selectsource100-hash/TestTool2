import hashlib
import secrets
import binascii
import asyncio
import aiohttp
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Tuple, List, Dict
from ecdsa import SigningKey, SECP256k1
import multiprocessing

# ----------------------------
# Bitcoin Utilities - OPTIMIZED
# ----------------------------

# Pre-compute base58 alphabet mapping for speed
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_MAP = {c: i for i, c in enumerate(BASE58_ALPHABET)}

def sha256_fast(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58_encode_fast(data: bytes) -> str:
    """Optimized base58 encoding"""
    num = int.from_bytes(data, 'big')
    
    # Pre-allocate list for better performance
    encoded_chars = []
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded_chars.append(BASE58_ALPHABET[remainder])
    
    # Add zeros
    for byte in data:
        if byte == 0:
            encoded_chars.append('1')
        else:
            break
    
    return ''.join(reversed(encoded_chars))

def private_key_to_wif_fast(private_key_hex: str, compressed: bool = True) -> str:
    extended_key = '80' + private_key_hex
    if compressed:
        extended_key += '01'
    extended_bytes = bytes.fromhex(extended_key)
    checksum = sha256_fast(extended_bytes)[:4]
    wif_bytes = extended_bytes + checksum
    return base58_encode_fast(wif_bytes)

def private_key_to_public_key_fast(private_key_bytes: bytes) -> str:
    """Direct bytes to compressed public key - fastest path"""
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = '02' if (y % 2 == 0) else '03'
    return prefix + format(x, '064x')

def public_key_to_address_fast(public_key_hex: str) -> str:
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()
    extended_hash = b'\x00' + hashed_public_key
    checksum = sha256_fast(extended_hash)[:4]
    address_bytes = extended_hash + checksum
    return base58_encode_fast(address_bytes)

def generate_keypair_batch(batch_size: int) -> List[Tuple[str, str, str]]:
    """Generate multiple keypairs in batch (used in parallel processes)"""
    results = []
    for _ in range(batch_size):
        private_key_bytes = secrets.token_bytes(32)
        private_key_hex = binascii.hexlify(private_key_bytes).decode()
        wif = private_key_to_wif_fast(private_key_hex, True)
        public_key = private_key_to_public_key_fast(private_key_bytes)
        address = public_key_to_address_fast(public_key)
        results.append((private_key_hex, wif, address))
    return results

# ----------------------------
# Async Balance Checkers - HIGHLY OPTIMIZED
# ----------------------------

APIS = [
    'https://blockstream.info/api/address/{}',
    'https://mempool.space/api/address/{}',
]

async def check_balance_batch(session: aiohttp.ClientSession, address: str, semaphore: asyncio.Semaphore) -> float:
    """Check balance with connection pooling and concurrency limiting"""
    async with semaphore:
        for api_url in APIS:
            try:
                url = api_url.format(address)
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=1)) as response:
                    if response.status == 200:
                        data = await response.json()
                        # Fastest balance extraction
                        chain_stats = data.get('chain_stats', {})
                        mempool_stats = data.get('mempool_stats', {})
                        balance = (chain_stats.get('funded_txo_sum', 0) - 
                                  chain_stats.get('spent_txo_sum', 0) +
                                  mempool_stats.get('funded_txo_sum', 0) - 
                                  mempool_stats.get('spent_txo_sum', 0))
                        if balance > 0:
                            return balance / 100000000
            except:
                continue
    return 0.0

async def process_batch_with_checks(batch_data: List[Tuple[str, str, str]], 
                                     session: aiohttp.ClientSession, 
                                     semaphore: asyncio.Semaphore) -> List[Dict]:
    """Process a batch of keys and check balances asynchronously"""
    tasks = []
    for pk, wif, addr in batch_data:
        tasks.append(check_balance_batch(session, addr, semaphore))
    
    balances = await asyncio.gather(*tasks)
    
    results = []
    for (pk, wif, addr), balance in zip(batch_data, balances):
        if balance > 0:
            results.append({
                'addr': addr,
                'balance': balance,
                'wif': wif,
                'pk': pk
            })
        # Optional: print progress for every key
        # print(f"✓ {addr[:10]}... {balance:.8f} BTC")
    
    return results

# ----------------------------
# Main Optimized Pipeline
# ----------------------------

async def async_main():
    print("=" * 60)
    print("BITCOIN KEY GENERATOR - HYPER OPTIMIZED (100+ keys/sec)")
    print("=" * 60)
    
    num_keys = int(input("How many keys to generate?: "))
    
    # Optimal batch sizes based on hardware
    cpu_count = multiprocessing.cpu_count()
    keys_per_batch = max(100, num_keys // (cpu_count * 4))  # Adjust batch size
    num_batches = (num_keys + keys_per_batch - 1) // keys_per_batch
    
    print(f"\n🚀 Running with {cpu_count} CPU cores, {keys_per_batch} keys/batch")
    print("=" * 60)
    
    total_balance = 0
    found_wallets = []
    start_time = time.time()
    
    # Setup async HTTP session with connection pooling
    connector = aiohttp.TCPConnector(limit=200, limit_per_host=50, ttl_dns_cache=300)
    semaphore = asyncio.Semaphore(200)  # Max concurrent API requests
    
    async with aiohttp.ClientSession(connector=connector) as session:
        # Use process pool for CPU-bound key generation
        with ProcessPoolExecutor(max_workers=cpu_count) as process_pool:
            
            keys_processed = 0
            for batch_idx in range(num_batches):
                current_batch_size = min(keys_per_batch, num_keys - keys_processed)
                
                # Generate keys in parallel using process pool
                loop = asyncio.get_event_loop()
                batch_keys = await loop.run_in_executor(
                    process_pool, 
                    generate_keypair_batch, 
                    current_batch_size
                )
                
                # Check balances asynchronously
                found = await process_batch_with_checks(batch_keys, session, semaphore)
                
                # Update results
                for wallet in found:
                    total_balance += wallet['balance']
                    found_wallets.append(wallet)
                
                keys_processed += current_batch_size
                
                # Progress report
                elapsed = time.time() - start_time
                speed = keys_processed / elapsed if elapsed > 0 else 0
                print(f"\r📊 Processed: {keys_processed}/{num_keys} | "
                      f"Speed: {speed:.1f} keys/sec | "
                      f"Found: {len(found_wallets)} | "
                      f"Time: {elapsed:.1f}s", end="", flush=True)
    
    # Summary
    elapsed = time.time() - start_time
    print("\n\n" + "=" * 60)
    print(f"✅ COMPLETE!")
    print(f"⏱️  Time: {elapsed:.2f} seconds")
    print(f"⚡ Speed: {num_keys/elapsed:.1f} keys/sec")
    print(f"🔑 Generated: {num_keys} keys")
    
    if found_wallets:
        print(f"\n💰 FOUND {len(found_wallets)} WALLETS WITH BALANCE!")
        print(f"💎 Total Balance: {total_balance:.8f} BTC")
        for wallet in found_wallets:
            print(f"\n  📍 Address: {wallet['addr']}")
            print(f"  💰 Balance: {wallet['balance']} BTC")
            print(f"  🔑 WIF: {wallet['wif']}")
            print(f"  🔐 Private Key: {wallet['pk']}")
    else:
        print("\n💀 No wallets with balance found")
    
    print("=" * 60)

def main():
    """Entry point with async support"""
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy') and hasattr(asyncio, 'set_event_loop_policy'):
        # Windows optimization
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(async_main())

if __name__ == "__main__":
    # Install required packages first:
    # pip install aiohttp ecdsa
    main()
