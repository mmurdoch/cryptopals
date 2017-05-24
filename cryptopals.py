import array
import base64


def byte_array():
    return array.array('B')

def hex_to_bytes(hex_string):
    return array.array('B', hex_string.decode('hex'))

def bytes_to_hex(bytes):
    return bytes.encode('hex')

def bytes_to_base64(bytes):
    return base64.b64encode(bytes)

def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))

def xor(hex_string_1, hex_string_2):
    bytes_1 = hex_to_bytes(hex_string_1)
    bytes_2 = hex_to_bytes(hex_string_2)

    result = byte_array()
    for i in range(len(bytes_1)):
        result.append(bytes_1[i] ^ bytes_2[i])

    return bytes_to_hex(result)

def assert_equal(expected, actual):
    if actual != expected:
        print('F')
        print('Expected ' + expected + ' but was ' + actual)

# Set 1, Challenge 1
assert_equal('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t', hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

# Set 1, Challenge 2
#assert_equal('746865206b696420646f6e277420706c6179', xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))
