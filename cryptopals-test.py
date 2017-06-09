from cryptopals import *


def assert_equal(expected, actual):
    if actual != expected:
        print('F')
        print('Expected \'' + str(expected) + '\' but was \'' + str(actual) + '\'')
    else:
        print('.')

# Utilities
assert_equal(type(byte_array()), type(hex_to_bytes('48650A')))
assert_equal(type(byte_array()), type(ascii_to_bytes('hello')))
assert_equal(type(byte_array()), type(base64_to_bytes('axis')))
assert_equal(['abc', 'def', 'ghi'], split_into_blocks('abcdefghi', 3))

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

# Set 1, Challenge 5
assert_equal('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f', xor_repeating_ascii_key_ascii_to_hex('ICE', 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'))

# Set 1, Challenge 6
assert_equal(37, hamming_distance_ascii_ascii('this is a test', 'wokka wokka!!!'))
def solve_challenge_6():
    base64_content = read_content('6.txt')
    bytes = base64_to_bytes(base64_content)
    key_size = crack_repeating_key_xor_key_size(bytes, 2, 40, 4)
    key = crack_repeating_key_xor_key(bytes, key_size)
    decrypted = crack_repeating_key_xor(bytes, key_size)
    return (bytes_to_ascii(key), bytes_to_ascii(decrypted))
 
challenge_6_solution = solve_challenge_6()
assert_equal('Terminator X: Bring the noise', challenge_6_solution[0])
assert_equal('I\'m back and I\'m ringin\' the bell', challenge_6_solution[1][0:33])

# Set 1, Challenge 7
# Note: Requires PyCrypto (pip install pycrypto)
def solve_challenge_7():
    base64_content = read_content('7.txt')
    bytes = base64_to_bytes(base64_content)
    key_bytes = ascii_to_bytes('YELLOW SUBMARINE')
    return decrypt_aes_ecb_bytes_to_ascii(key_bytes, bytes)

assert_equal('I\'m back and I\'m ringin\' the bell', solve_challenge_7()[0:33])

# Set 1, Challenge 8
def solve_challenge_8():
    hex_lines = read_lines('8.txt')
    for i in range(len(hex_lines)):
        hex_line = hex_lines[i]
        bytes = hex_to_bytes(hex_line_to_hex(hex_line))
        blocks = split_into_blocks(bytes, 16)
        sorted_blocks = sorted(blocks)
        for j in range(len(sorted_blocks)-1):
            if sorted_blocks[j] == sorted_blocks[j+1]:
                return i+1

assert_equal(133, solve_challenge_8())

# Set 2, Challenge 9
def solve_challenge_9():
    bytes = ascii_to_bytes('YELLOW SUBMARINE')
    padded_bytes = pad_to_bytes(bytes, 20)
    return bytes_to_ascii(padded_bytes)

assert_equal('YELLOW SUBMARINE\x04\x04\x04\x04', solve_challenge_9())
 
