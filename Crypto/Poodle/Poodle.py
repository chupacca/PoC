import base64
import VulnAESwithCBC
from VulnAESwithCBC import AESwithCBC
 

#Object that exploits the Poodle Vulnerability
class Poodle(object):

	#Constructor
	#encryptedText: The ciphertext to be broken
	#aes: the cipher in order to decrypt
	#iv: the cipher's initizlization vector
	def __init__(self, ciphertext, cipher, iv):

		self.__ciphertext = ciphertext
		self.__cipher = cipher
		self.__iv = iv


	#Splits the incoming text into blocks of 16 because of AES and padding will be added if not a multiple of 16.
	#text: the text that will be split into blocks of 16
	def __splitTheBlocks(self, text):

		length = len(text)
		aesBlocks = []
		
		for i in range(length / 16):
			startIdx = i * 16
			endIdx = (i + 1) * 16
			aesBlocks.append(text[startIdx:endIdx])

		return aesBlocks

	#Does xor operation 
	#blockOne: the first block
	#blockTWo: the second block
	def __doXOR(self, blockOne, blockTwo):

		b1 = bytearray(blockOne)
		b2 = bytearray(blockTwo)

		return bytearray([b1[i] ^ b2[i] for i in range(len(b1))])

	#Executes the exploit
	def exploit(self):

		ciText = bytearray(self.__iv) + bytearray(base64.b64decode(self.__ciphertext)) #ciphertext
		blocks = self.__splitTheBlocks(ciText) #ciphertext split into blocks

		plaintext = ""

		'''
		#plaintext += self.guessBytes(blocks[0:])
		plaintext += self.guessBytes(blocks[0:2]) #block2
		plaintext += self.guessBytes(blocks[1:3]) #block3
		plaintext += self.guessBytes(blocks[2:4]) #block4
		plaintext += self.guessBytes(blocks[3:5]) #block5
		'''

		#Iterate over the blocks
		for i in range(len(blocks) - 1):
			plaintext += self.guessBytes(blocks[i: i + 2])
		
		return plaintext

	#Guesses the bytes between two blocks to crack the cipher
	def guessBytes(self, ciBlocks):

		ciPrime = bytearray([i for i in ciBlocks[0]]) #The modified block

		plainBytes = bytearray([0 for _ in range(16)]) #the plaintext that will be appended to

		#The index range of every block because 16 is the maximum length of a pad
		for i in range(16):

			#The possible paddings. You don't want to xor the byte we're changing
			padding = [0 for _ in range(16 - i)] + [(i + 1) for _ in range(i)]

			#Calculating what c prime is given the other factors are
			ciPrime = self.__doXOR(self.__doXOR(padding, plainBytes), ciBlocks[0])

			#This for loop is to make a guess. It is 256 because a traditional byte has 8 bits and 2^8 is 256
			for guess in range(0, 256):
				
				ciPrime[15 - i] = guess #change the relevant bit

				test = base64.b64encode(ciPrime + ciBlocks[1]) #The modified block is added with the rest

				#!!!!!!!!!THIS IS WHERE AN ADVERSARY USES THE ERROR TO KNOW WHEN THEIR GUESS IS CORRECT
				try: 
					self.__cipher.decrypt(test, self.__iv)
					plainBytes[15 - i] = guess ^ (i + 1) ^ ciBlocks[0][15 - i]
					break

				except ValueError: #THE ERROR THAT WAS WARNED ABOUT IN THE VulnAESwithCBC code (line 63 & 71)
					pass

		return ''.join([chr(b) for b in plainBytes if b > 16]) #return string of cracked text