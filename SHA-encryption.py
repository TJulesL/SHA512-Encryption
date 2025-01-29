
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import multiprocessing
import time
import os
 
 
 
 
# mutli process
def generate_round_keys(base_key: bytes, num_keys: int, key_length: int = 64) -> list:
    """Generate round keys using PBKDF2 key derivation with a salt derived from the base key.
 
    Args:
        base_key (bytes): The base key (seed) for deriving round keys.
        num_keys (int): The number of round keys to generate.
        key_length (int): Length of each key in bytes (default: 64).
 
    Returns:
        list: List of generated round keys.
    """
    # Hash the base key to create a fixed salt
    salt = hashlib.sha3_512(base_key).digest()  # Use the SHA3-512 hash of the base key as the salt
    round_keys = []
 
    for i in range(num_keys):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=key_length,
            salt=salt,
            iterations=10,
            backend=default_backend()
        )
 
        # Derive a round key using the base key and the index
        round_key = kdf.derive(base_key + i.to_bytes(4, 'big'))  # Use the index as part of the input
        round_keys.append(round_key)
 
    keys = []
    for round_key in round_keys:
        keys.append([int.from_bytes([byte], 'little') for byte in round_key])
 
    return keys
 
 
 
 
 

def xor_barray_func(half_block, round_key):
    return [a ^ b for a, b in zip(half_block, round_key)]
 
#xor_barray_func = lambda half_block, round_key: [np.bitwise_xor(a, b) for a, b in zip(half_block, round_key)]


def feistel_f_function(half_block: bytearray, round_key: bytearray) -> str:
    assert len(half_block) == len(round_key), f"The block and round key both have to be 64 bytes (512 bits) not {len(half_block)} and {len(round_key)}"
    """F function
 
    Args:
        half_block (bytearray): A (512 bit) Block 
        round_key (list): Current round key in format of an int list (512 bits)
 
    Returns:
        output hash (bytes): output in bytes
    """
    return hashlib.sha3_512(bytes(xor_barray_func(half_block, round_key))).digest()
 
 
 
# multi process
def crypt_block(block: bytearray, round_keys: list, mode: str) -> bytearray:
    """ Block encryption/decryption
 
    Args:
        block (bytearray): The full block in a bytearray
        round_keys (list): list of all the round keys
        mode (str): 'e' for encrypt, 'd' for decrypting
 
    Returns:
        output_block (bytearray): output in a bytearray
    """
    rounds = len(round_keys)
 
    if mode == 'e':
        left, right = block[:64], block[64:]
    if mode == 'd':
        right, left = block[:64], block[64:]
        round_keys.reverse()
    else:
        assert ValueError("No correct argument given for encrypting or decrypting (mode='e' or 'd')")
 
    for i in range(rounds):
        # encrypt right with feistel f function / round key
        f_right = feistel_f_function(right, round_keys[i])
 
        # xor with left 
        left = xor_barray_func(left, f_right)   
        # if in the last round dont switch
        if i != (rounds - 1):
            left, right = right, left
 
    if mode == 'e':
        block = right + left
    if mode == 'd':
        block = left + right
 
    return [bytearray(block)]
 
 
 
 
 
def data_to_blocks(data, block_size: int = 128) -> list:
    if type(data) == str:
        # if str -> bytes
        data = data.encode()
 
    if len(data) % block_size != 0 or len(data) == 0:
        # add padding
        padding_len = block_size - (len(data) % block_size)
        if len(data) == 0:
            padding_len = 128
        padding = bytes([padding_len] * padding_len)
        data = data + padding
 
    blocks = []
 
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        blocks.append(block)
 
    return blocks
 
 
def remove_padding(data_blocks: list[bytes]) -> bytearray:
    """removes padding
 
    Args:
        data_blocks (list[bytes]): Blocks of data after decryption
 
    Returns:
        bytearray: bytearray of all blocks without padding
    """
    if not data_blocks:
        raise ValueError("The data_blocks list is empty")
 
    result_blocks = data_blocks[:-1]
    last_block = data_blocks[-1]
 
    if not last_block:
        raise ValueError("The last block is empty and cannot have valid padding")
 
    padding_len = last_block[-1]
    if padding_len < 1 or padding_len > len(last_block):
        raise ValueError("Invalid padding length")
 
    if last_block[-padding_len:] != bytes([padding_len] * padding_len):
        return data_blocks
 
    last_block = last_block[:-padding_len]
    result_blocks.append(last_block)    
 
    return result_blocks
 
 
 
 
 
 
if __name__ == '__main__':
    blocks = data_to_blocks(input("Input : "))
    keys = generate_round_keys(input("Key : ").encode(), 16)
    start_time = time.time()
    p = multiprocessing.Pool(processes=os.cpu_count())
    with p as pool:
        result = pool.starmap(crypt_block, [(block, keys, 'e') for block in blocks])
    parallel_time = time.time() - start_time
    print(f"Parallel processing took {parallel_time:.4f} seconds")
    for i in range(0, len(result)):
        print(f"Block {i} : ",result[i][0].hex(),"\n")
