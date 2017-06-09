import array
import base64
import binascii
import itertools
from Crypto.Cipher import AES

def byte_array():
    return array.array('B')

def ascii_to_bytes(ascii):
    return array.array('B', ascii)

def hex_to_bytes(hex):
    return ascii_to_bytes(hex.decode('hex'))

def hex_line_to_hex(hex_line):
    return hex_line.rstrip()

def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def hex_to_ascii(hex):
    return bytes_to_ascii(hex_to_bytes(hex))

def base64_to_bytes(b64):
    return ascii_to_bytes(base64.b64decode(b64))

def bytes_to_hex(bytes):
    return binascii.hexlify(bytes)

def bytes_to_base64(bytes):
    return base64.b64encode(bytes)

def bytes_to_ascii(bytes):
    ascii = ''
    for byte in bytes:
        ascii += chr(byte)

    return ascii

def pad_to_bytes(bytes, padded_length):
    unpadded_length = len(bytes)
    pad_length = padded_length - unpadded_length

    padded_bytes = bytes[:]

    for i in range(pad_length):
        padded_bytes.append(pad_length)

    return padded_bytes


def xor_byte_byte(byte_1, byte_2):
    return byte_1 ^ byte_2

def xor_byte_bytes(byte, bytes):
    result = byte_array()
    for b in bytes: 
        result_byte = xor_byte_byte(byte, b)
        result.append(result_byte)

    return result

def xor_bytes_bytes(bytes_1, bytes_2):
    result = byte_array()
    for i in range(len(bytes_2)):
        result.append(xor_byte_byte(bytes_1[i], bytes_2[i]))

    return result

def xor_hex_hex(hex_1, hex_2):
    bytes_1 = hex_to_bytes(hex_1)
    bytes_2 = hex_to_bytes(hex_2)

    result_bytes = xor_bytes_bytes(bytes_1, bytes_2)

    return bytes_to_hex(result_bytes)

def xor_repeating_ascii_key_ascii_to_hex(ascii_key, ascii):
    key = ascii_to_bytes(ascii_key)
    bytes = ascii_to_bytes(ascii)

    key_index = 0

    result = byte_array()
    for byte in bytes:
        if key_index == len(key):
            key_index = 0

        key_byte = key[key_index]
        result.append(xor_byte_byte(key_byte, byte))

        key_index += 1

    return bytes_to_hex(result)

def hamming_distance_byte_byte(byte_1, byte_2):
    count = 0
    not_completed = byte_1 ^ byte_2 
    while not_completed:
        count += 1
        not_completed &= not_completed - 1

    return count

def hamming_distance_bytes_bytes(bytes_1, bytes_2):
    assert(len(bytes_1) == len(bytes_2))

    count = 0
    for byte_pair in zip(bytes_1, bytes_2):
        count += hamming_distance_byte_byte(byte_pair[0], byte_pair[1])

    return count 

def hamming_distance_ascii_ascii(ascii_1, ascii_2):
    bytes_1 = ascii_to_bytes(ascii_1)
    bytes_2 = ascii_to_bytes(ascii_2)

    return hamming_distance_bytes_bytes(bytes_1, bytes_2)

def score_ascii_as_english(ascii):
    english_letter_frequencies = 'zqxjkvbpygfwmucldrhsnioate '

    score = 0

    for char in ascii.lower():
        if char in english_letter_frequencies:
            score += english_letter_frequencies.index(char) + 1

    return float(score)/len(ascii)

def score_bytes_as_english(bytes):
    return score_ascii_as_english(bytes_to_ascii(bytes))

def read_lines(filename):
    with open(filename, 'r') as f:
        return f.readlines()

def read_content(filename):
    content = ''

    lines = read_lines(filename)
    for line in lines:
        content += line

    return content

def index_of_max(list):
    return list.index(max(list))

def split_into_blocks(bytes, block_size):
    return [bytes[i:i+block_size] for i in range(0, len(bytes), block_size)]

def transpose_blocks(blocks):
    transposed = []
    for i in range(0, len(blocks[0])):
        transposed.append(byte_array())

    for block in blocks:
        i = 0
        for byte in block:
            transposed[i].append(byte)
            i += 1

    return transposed

def decrypt_aes_ecb_bytes_to_ascii(key_bytes, bytes):
    return AES.new(key_bytes, AES.MODE_ECB).decrypt(bytes)

def crack_xor_byte_hex_line_to_bytes(hex_line):
    return crack_xor_byte_hex_to_bytes(hex_line_to_hex(hex_line))

def crack_xor_byte_hex_to_bytes(hex):
    bytes = hex_to_bytes(hex)
    return crack_xor_byte_bytes_to_bytes(bytes)

def crack_xor_byte_hex_to_ascii(hex):
    cracked_bytes = crack_xor_byte_hex_to_bytes(hex)
    return bytes_to_ascii(cracked_bytes)

def crack_xor_byte_bytes_to_bytes(bytes):
    key = crack_xor_byte_bytes(bytes)
    return xor_byte_bytes(key, bytes)

def crack_xor_byte_bytes(bytes):
    scores = []

    for key_byte in range(0, 256):
        decoded = xor_byte_bytes(key_byte, bytes)
        key_score = score_bytes_as_english(decoded)
        scores.append(key_score)

    return index_of_max(scores)

def likely_repeating_key_xor_key_sizes(bytes, min_key_size, max_key_size, key_count):
    hamming_distances = []

    key_sizes = range(min_key_size, max_key_size)
    for key_size in key_sizes:
        blocks = split_into_blocks(bytes, key_size)
        byte_count_to_average = 4
        hamming_distance = 0
        for i in range(byte_count_to_average):
            hamming_distance += hamming_distance_bytes_bytes(blocks[i], blocks[i+1])
        hamming_distances.append(float(hamming_distance)/(byte_count_to_average*key_size))

    return sorted(key_sizes, key=lambda key_size: hamming_distances[key_size-min_key_size])[:key_count]

def crack_repeating_key_xor_key_size(bytes, min_key_size, max_key_size, key_sizes_to_try_count):
    key_sizes_to_try = likely_repeating_key_xor_key_sizes(
        bytes, min_key_size, max_key_size, key_sizes_to_try_count)

    key_scores = []

    for key_size in key_sizes_to_try:
        key = crack_repeating_key_xor_key(bytes, key_size)
        decrypted = crack_repeating_key_xor(bytes, key_size)
        key_score = score_bytes_as_english(decrypted)
        key_scores.append(key_score)

    return key_sizes_to_try[index_of_max(key_scores)]

def crack_repeating_key_xor_key(bytes, key_size):
    blocks = split_into_blocks(bytes, key_size)
    transposed_blocks = transpose_blocks(blocks)
    key = byte_array() 
    for transposed_block in transposed_blocks:
        key.append(crack_xor_byte_bytes(transposed_block))

    return key

def crack_repeating_key_xor(bytes, key_size):
    key = crack_repeating_key_xor_key(bytes, key_size)
    decrypted = byte_array()

    blocks = split_into_blocks(bytes, key_size)
    for block in blocks:
        decrypted_block = xor_bytes_bytes(key, block)
        for byte in decrypted_block:
            decrypted.append(byte)

    return decrypted
