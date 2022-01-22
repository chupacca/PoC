#!/usr/bin/python3

import math
import sys


# The frequency each letter occurs in the English language
LETTER_FREQUENCY = {
    "a" : 0.08167,
    "b" : 0.01492,
    "c" : 0.02782,
    "d" : 0.04253,
    "e" : 0.12702,
    "f" : 0.02228,
    "g" : 0.02015,
    "h" : 0.06094,
    "i" : 0.06966,
    "j" : 0.00153,
    "k" : 0.00772,
    "l" : 0.04025,
    "m" : 0.02406,
    "n" : 0.06749,
    "o" : 0.07507,
    "p" : 0.01929,
    "q" : 0.00095,
    "r" : 0.05987,
    "s" : 0.06327,
    "t" : 0.09056,
    "u" : 0.02758,
    "v" : 0.00978,
    "w" : 0.02360,
    "x" : 0.00150,
    "y" : 0.01974,
    "z" : 0.00074
}



# Print the frequencies of each letter of the English alphabet
def print_frequencies():
    for entry in LETTER_FREQUENCY:
        print("key: " + entry + " | " + str(LETTER_FREQUENCY[entry]))



# Shift the given character by taking the type of ASCII char and the length of the
#   English alphabet (26) into account. This character shifts left past the letter a/A it will
#   wrap around to the end of the alphabet.
#
# char_ascii(int): the ascii value of the character
# min_ascii_value(int): 65 (uppercase letter ascii floor) or 97 (lowercase letter ascii floor)
# shift_number(int): how letters to shift the letters
#
# return the ascii value that represents the shifted character
def shift_char(char_ascii, min_ascii_value, shift_number):

    # Take the character's ascii value and subtract the floor of the ascii value (65 or 97)
    #  keep in mind 65 is the floor for uppercase letters
    #  keep in mind 97 is the floor for lowercase letters
    int_a = char_ascii - min_ascii_value # example: 'b' - ASCII_FLOOR = 98 - 97 = 1
    int_a = int_a - shift_number # if char is b and shift value is 1 -> b is meant to become a

    return int_a % 26 # mod by 26 so this value stays within the English alphabet



# Shift the strings left by a given number
# ciphertext(string): the text that has had caesar's cipher applied
# shift_number(int): how many values to shift the string left by
#
# returns a string that represents the shifted string by the shift_number
def shift_string(ciphertext, shift_number):

    result = "" # stores the resulting shifted string (will be appended to)

    # Will iterate over the ciphertext and shift each character individually
    for char in ciphertext:

        int_char = ord(char) # convert char to its int value

        # ASCII for uppercase
        if int_char >= 65 and int_char <=  90:

            shifted_value = shift_char(int_char, 65, shift_number) # shift the character
            ascii_value = shifted_value + 65 # covert mod value back to integer of uppercase

            result += chr(ascii_value) # append to final shifted string


        # ASCII for lowercase
        elif int_char >= 97 and int_char <= 122:

            shifted_value = shift_char(int_char, 97, shift_number)
            ascii_value = shifted_value + 97  # covert mod value back to integer of lowercase

            result += chr(ascii_value) # append to final shifted string


        # If not a letter just append it to the result
        else:
            result += char

    return result



# Calculates the entropy for a given string
# text(string): the string to calculate the entropy value for
#
# return a float value that represents the entropy value
def get_entropy(text):

    cumlative_entropy = 0 # the variable that will hold the summation of each character's entropy
    num_not_letters = 0


    for char in text:

        int_char = ord(char) # get ascii value of the character

        # ASCII values of upper case letters
        if int_char >= 64 and int_char <= 90:

            #print("Upper case letter for " + char + " found. Making lower case")
            #print("Letter: " + str(lower_char) +
            #      " | Frequency: " + str(LETTER_FREQUENCY[lower_char]))

            lower_char = char.lower() # if we have an uppercase letter, make it lower case
            cumlative_entropy += math.log(LETTER_FREQUENCY[lower_char]) # do a log function on the frequency of the character

        # ASCII values of lower case letters
        elif int_char >= 97 and int_char <= 122:
            #print("Letter: " + str(char) +
            #      " | Frequency: " + str(LETTER_FREQUENCY[char]))

            cumlative_entropy += math.log(LETTER_FREQUENCY[char]) # do a log function on the frequency of the character

        else:
            print("Ignoring non-letter character: " + char)
            num_not_letters +=1

    letter_length = len(text) - num_not_letters # find the length that doesn't include letters
    return -cumlative_entropy / math.log(2) / letter_length


# Get the entropy values for all 26 shift values of the given string (assumes only 26 character string)
# ciphertext(string): the string that has been encrypted with caesar's ciphter
def get_all_entropies(ciphertext):

    smallest_entropy_text = "" # the text of the string with the lowest entropy
    smallest_entropy_value = 100; # temporary store a value


    for shift_value in range(0, 26): # this loop should go from 0 to 25

        shifted_text = shift_string(ciphertext, shift_value)
        entropy_value = get_entropy(shifted_text)


        if(shift_value == 0): # do this on the first iteration; to store initial value
            smallest_entropy_text = shifted_text
            smallest_entropy_value = entropy_value
        else:
            if entropy_value < smallest_entropy_value:
                smallest_entropy_text = shifted_text
                smallest_entropy_value = entropy_value

    return smallest_entropy_text


def main(argv):

    # test case: $ python3 caesar_cracker.py ifmmp
    # test case output: hello
    encrypted_text = argv[0]
    decrypted_text = get_all_entropies(encrypted_text)

    print("Decrypted Text: " + decrypted_text)
    print("===== Done =====")


if __name__ == "__main__":
    main(sys.argv[1:])
