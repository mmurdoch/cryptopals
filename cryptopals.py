import array
import base64
import binascii

def byte_array():
    return array.array('B')

def hex_to_bytes(hex):
    return array.array('B', hex.decode('hex'))

def hex_line_to_hex(hex_line):
    return hex_line.rstrip()

def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def hex_to_ascii(hex):
    return bytes_to_ascii(hex_to_bytes(hex))

def bytes_to_hex(bytes):
    return binascii.hexlify(bytes)

def bytes_to_base64(bytes):
    return base64.b64encode(bytes)

def bytes_to_ascii(bytes):
    return binascii.b2a_qp(bytes)

def xor_byte_bytes(byte, bytes):
    result = byte_array()
    for b in bytes: 
        result_byte = byte ^ b
        result.append(result_byte)

    return result

def xor_bytes_bytes(bytes_1, bytes_2):
    result = byte_array()
    for i in range(len(bytes_1)):
        result.append(bytes_1[i] ^ bytes_2[i])

    return result

def xor_hex_hex(hex_1, hex_2):
    bytes_1 = hex_to_bytes(hex_1)
    bytes_2 = hex_to_bytes(hex_2)

    result_bytes = xor_bytes_bytes(bytes_1, bytes_2)

    return bytes_to_hex(result_bytes)

def score_ascii_as_english(ascii):
    english_letter_frequencies = 'zqxjkvbpygfwmucldrhsnioate '

    score = 0

    for char in ascii.lower():
        if char in english_letter_frequencies:
            score += english_letter_frequencies.index(char) + 1

    return float(score)/len(ascii)

def score_bytes_as_english(bytes):
    return score_ascii_as_english(bytes_to_ascii(bytes))

def index_of_max(list):
    return list.index(max(list))

def crack_xor_byte_hex_line_to_bytes(hex_line):
    return crack_xor_byte_hex_to_bytes(hex_line_to_hex(hex_line))

def crack_xor_byte_hex_to_bytes(hex):
    bytes = hex_to_bytes(hex)

    scores = []

    for key_byte in range(0, 256):
        decoded = xor_byte_bytes(key_byte, bytes)
        decoded_ascii = bytes_to_ascii(decoded)
        key_score = score_bytes_as_english(decoded_ascii)
        scores.append(key_score)

    best_key = index_of_max(scores)

    return xor_byte_bytes(best_key, bytes)

def crack_xor_byte_hex_to_ascii(hex):
    cracked_bytes = crack_xor_byte_hex_to_bytes(hex)
    return bytes_to_ascii(cracked_bytes)

def assert_equal(expected, actual):
    if actual != expected:
        print('F')
        print('Expected \'' + expected + '\' but was \'' + actual + '\'')
    else:
        print('.')

# Set 1, Challenge 1
assert_equal('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
    hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

# Set 1, Challenge 2
assert_equal('746865206b696420646f6e277420706c6179', 
    xor_hex_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))

# Set 1, Challenge 3
assert_equal('Cooking MC\'s like a pound of bacon', 
    crack_xor_byte_hex_to_ascii('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

# Set 1, Challenge 4
def solve_challenge_4():
    with open('4.txt', 'r') as f:
        lines = f.readlines()
        scores = []
        for line in lines:
            cracked_bytes = crack_xor_byte_hex_line_to_bytes(line)
            score = score_bytes_as_english(cracked_bytes)
            scores.append(score)
        best_line = lines[index_of_max(scores)]
        return bytes_to_ascii(
            crack_xor_byte_hex_line_to_bytes(best_line))
assert_equal('Now that the party is jumping\n', solve_challenge_4())
