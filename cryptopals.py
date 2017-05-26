import array
import base64
import binascii

def byte_array():
    return array.array('B')

def hex_to_bytes(hex_string):
    return array.array('B', hex_string.decode('hex'))

def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))

def bytes_to_hex(bytes):
    return binascii.hexlify(bytes)

def bytes_to_base64(bytes):
    return base64.b64encode(bytes)

def bytes_to_string(bytes):
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

def xor_hex_hex(hex_string_1, hex_string_2):
    bytes_1 = hex_to_bytes(hex_string_1)
    bytes_2 = hex_to_bytes(hex_string_2)

    result_bytes = xor_bytes_bytes(bytes_1, bytes_2)

    return bytes_to_hex(result_bytes)

def score_bytes_as_english(bytes):
    english_letter_frequencies = 'zqxjkvbpygfwmucldrhsnioate '

    string = bytes_to_string(bytes)

    score = 0

    for char in string.lower():
        if char in english_letter_frequencies:
            score += english_letter_frequencies.index(char) + 1

    return float(score)/len(string)

def crack_xor_byte_hex(encoded_hex_string):
    bytes = hex_to_bytes(encoded_hex_string)

    scores = []

    for key_byte in range(0, 256):
        decoded = xor_byte_bytes(key_byte, bytes)
        decoded_string = bytes_to_string(decoded)
        key_score = score_bytes_as_english(decoded_string)
        scores.append(key_score)

    best_key = scores.index(max(scores))

    return bytes_to_string(xor_byte_bytes(best_key, bytes))

def assert_equal(expected, actual):
    if actual != expected:
        print('F')
        print('Expected ' + expected + ' but was ' + actual)
    else:
        print('.')

# Set 1, Challenge 1
assert_equal('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t', hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

# Set 1, Challenge 2
assert_equal('746865206b696420646f6e277420706c6179', xor_hex_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))

# Set 1, Challenge 3
assert_equal('Cooking MC\'s like a pound of bacon', crack_xor_byte_hex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
