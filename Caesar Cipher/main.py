# Caesar Cipher
# Caesar cipher is an encryption technique that use substitution of letters to make a plaintext into
# non-human readable texts (ciphering). The method of encryption is substituting every letter
# with another letter which have a fixed of different number position in the alphabet
# Example : A right shift of three letters would make letter A into C, B into E and so on
# https://en.wikipedia.org/wiki/Caesar_cipher
#
#
# This Caesar cipher has a key of an integer 1 to 25.
# and rotates the letters of the alphabet (A to Z).
# For example, the letter AB with key of 2 would be replaced with CD
# There is no security provided with this type of mono alphabetic substitution cipher
# because an attacker who has the ciphered text can decipher either using frequency analysis
# to guess the key, or just brute forcing with 25 keys
B64_INDEXES = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
               'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
               'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
               'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
               's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
               '3', '4', '5', '6', '7', '8', '9', '+', '/')

FLAG_FILE = open("flag.txt", mode="r", encoding="utf-8")
KEY_FILE = open("key.txt", mode="r", encoding="utf-8")
CIPHER_KEY = int(KEY_FILE.read())
PLAIN_TEXT = FLAG_FILE.read().rstrip()


# Base64 encoding
# https://medium.com/swlh/base64-encoding-algorithm-42abb929087d

def strings_to_chars(plaintext):
    """
    Return a list of chars
    """
    chars = list()
    for char in plaintext:
        chars.append(char)
    return chars


def ascii_to_binary(chars):
    """
    Return a string of binary numbers
    """
    binary_str = ""
    bit_num = 8

    for char in chars:
        binary_letter = bin(ord(char)).replace("0b", "0")
        if len(binary_letter) < bit_num:
            binary_str += "0" + binary_letter
        else:
            binary_str += binary_letter
    return binary_str


def is_divided_by_six(binary_str):
    """
    Check if the entire binary strings
    are not able to be divided by 6
    """
    string_length = len(binary_str)
    bit_num = 6
    if string_length % bit_num != 0:
        return True
    else:
        return False


def divide_binary_sets(binarylist):
    """
    Divide binary strings into a
    6 bit sets and convert to
    into a list of decimal numbers
    """
    final_str = ""
    decimal_num = list()
    slice_num = 6
    min_list_index = 4

    # Extract every six index list
    for index_list in range(len(binarylist)):
        if (index_list + 1) % slice_num == 0 and index_list + 1 > min_list_index:
            final_str += binarylist[index_list]
            decimal_num.append(int(final_str, 2))
            final_str = ""
        else:
            final_str += binarylist[index_list]

    return decimal_num


def b64_encode(plaintext):

    padding = 0
    encoded = ""

    # Convert plain text strings to chars
    # because strings are immutable
    chars = strings_to_chars(plaintext)

    binary_str = ascii_to_binary(chars)

    # Add carriage return (new line)
    binary_str += "00001010"

    # Check the entire binary sets
    if not is_divided_by_six(binary_str):
        padding = padding + 1
        # complement binary string
        binary_str += "00"

    binary_list = list(binary_str)

    binarySets = divide_binary_sets(binary_list)

    # Begin encoding
    for binarySet in binarySets:
        for b64_index in range(len(B64_INDEXES)):
            if binarySet == b64_index:
                encoded += B64_INDEXES[b64_index]

    # add padding
    encoded += "=" * padding

    return encoded


def b64_letter_to_binary(text_list):
    """
    Convert B64 letter numbers to binary strings
    """
    binary_str = ""
    for text in text_list:
        if text != "=":
            for b64_index in range(len(B64_INDEXES)):
                if text == B64_INDEXES[b64_index]:
                    binary_str += format(b64_index, '06b')
    return binary_str


def eight_bit_binary(binary_list):
    """
    Convert the binary list into an
    8 bit of binary string list
    """
    eight_bit_str = ""
    letter_list = list()
    slice_num = 8
    min_list_index = 6
    for list_index in range(len(binary_list)):
        if (list_index + 1) % slice_num == 0 and list_index + 1 > min_list_index:
            eight_bit_str += binary_list[list_index]
            letter_list.append(eight_bit_str)
            eight_bit_str = ""
        else:
            eight_bit_str += binary_list[list_index]

    return letter_list


def b64_decode(text):

    decoded = ""

    text_list = list(text)

    binary_str = b64_letter_to_binary(text_list)

    binary_list = list(binary_str)

    letter_list = eight_bit_binary(binary_list)

    # Convert into ascii
    for letter in letter_list:
        decoded += chr(int(letter, 2))

    return decoded


def caesar_cipher(encoded_text, key):
    cipher = ""
    for char in list(encoded_text):
        cipher += str(chr(ord(char) + key))
    return cipher


def caesar_decipher(ciphered_text, key):
    decipher = ""
    for letter in list(ciphered_text):
        decipher += str(chr(ord(letter) - key))
    return decipher


def caesar_decipher_bruteforce(ciphered_text):
    decipher_text = ""
    decipher_text_list = []
    for num_key in range(1, 26):
        for char in list(ciphered_text):
            decipher_text += (str(chr(ord(char) - num_key)))
        decipher_text_list.append(decipher_text)
        decipher_text = ""
    return decipher_text_list


if __name__ == '__main__':
    print("Plain Text      : ", PLAIN_TEXT)
    print("Base64 Encoded  : ", b64_encode(PLAIN_TEXT))
    cipher_output = caesar_cipher(b64_encode(PLAIN_TEXT), CIPHER_KEY)
    print("Caesar Cipher   : ", cipher_output)
    decipher_output = caesar_decipher(cipher_output, CIPHER_KEY)
    print("Caesar Decipher : ", decipher_output)

    with open("decipher_flag.txt", mode="w", encoding="utf-8") as decipher_file_in:
        decipher_file_in.write(cipher_output)

    with open("decipher_flag.txt", mode="r", encoding="utf-8") as decipher_file_out:
        decipher_file_text = decipher_file_out.read().rstrip()

    print("Caesar Decipher (bruteforce) :")
    print("---------------------------------------------")
    for index, items in enumerate(caesar_decipher_bruteforce(decipher_file_text)):
        print(f"Key [{index + 1}] : {items}")
    print("---------------------------------------------")

    print("Base64 Decoded  : ", b64_decode(decipher_output))
