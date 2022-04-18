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
B64_INDEX = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
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

def b64_encode(text):
    bin_str = ""
    six_bit_str = ""
    encoded = ""
    padding = 0
    dec_list = []

    # Convert from ascii to binary numbers
    for words in list(text):
        for letter in list(words):
            bin_letter = bin(ord(letter)).replace("0b", "0")
            if len(bin_letter) < 8:
                bin_str += "0" + bin_letter
            else:
                bin_str += bin_letter

    # Add carriage return (new line)
    # bin_str += "00001010"

    # Check if the entire binary sets
    # are not able to be divided by 6
    if len(bin_str) % 6 != 0:
        while len(bin_str) % 6 != 0:
            padding = padding + 1
            bin_str += "00"

    bin_list = list(bin_str)

    # Divide each binary strings into
    # 6 bit sets and convert into decimal
    # numbers
    for i in range(len(bin_list)):
        if (i + 1) % 6 == 0 and i + 1 > 4:
            six_bit_str += bin_list[i]
            dec_list.append(int(six_bit_str, 2))
            six_bit_str = ""
        else:
            six_bit_str += bin_list[i]

    for item in dec_list:
        for i in range(len(B64_INDEX)):
            if item == i:
                encoded += B64_INDEX[i]

    # add padding
    encoded += "=" * padding

    return encoded


def b64_decode(text):
    text_list = list(text)
    bin_str = ""
    eight_bit_str = ""
    letter_list = []
    decoded = ""

    # Reverse the encoding
    # B64_INDEX letter numbers would be converted
    # to binaries
    for i in range(len(text_list)):
        if text_list[i] != "=":
            for j in range(len(B64_INDEX)):
                if text_list[i] == B64_INDEX[j]:
                    bin_str += format(j, '06b')

    bin_list = list(bin_str)

    # Divide the string into 8 bit length
    # of binary
    for i in range(len(bin_list)):
        if (i + 1) % 8 == 0 and i + 1 > 6:
            eight_bit_str += bin_list[i]
            letter_list.append(eight_bit_str)
            eight_bit_str = ""
        else:
            eight_bit_str += bin_list[i]

    # Convert into ascii
    for item in letter_list:
        decoded += chr(int(item, 2))

    return decoded


def caesar_cipher(encoded_text):
    cipher = ""
    for letter in list(encoded_text):
        cipher += str(chr(ord(letter) + CIPHER_KEY))
    return cipher


def caesar_decipher(ciphered_text):
    decipher = ""
    for letter in list(ciphered_text):
        decipher += str(chr(ord(letter) - CIPHER_KEY))
    return decipher


def caesar_decipher_bruteforce(ciphered_text):
    decipher = ""
    decipher_list = []
    for num_key in range(1, 27):
        for letter in list(ciphered_text):
            decipher += (str(chr(ord(letter) - num_key)))
        decipher_list.append(decipher)
        decipher=""
    return decipher_list


if __name__ == '__main__':
    print("Base64 Encoded  : ", b64_encode(PLAIN_TEXT))
    cipher_output = caesar_cipher(b64_encode(PLAIN_TEXT))
    print("Caesar Cipher   : ", cipher_output)
    decipher_output = caesar_decipher(cipher_output)
    print("Caesar Decipher : ", decipher_output)
    # print("Caesar Decipher (bruteforce) :\n", caesar_decipher_bruteforce(cipher_output))
    print("Base64 Decoded  : ", b64_decode(decipher_output))
