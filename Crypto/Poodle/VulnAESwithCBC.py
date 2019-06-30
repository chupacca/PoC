#Python 2.7
#pip install PyCrypto
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import base64

#Object that encrypts AES in CBC Mode (does Mac then Encrypt)
class AESwithCBC(object):

	#Constructor
	#key: can accept a key, but if none give, one is generated
	#hmacKey: the key for the HMAC
	def __init__(self, key = get_random_bytes(32), hmacKey = get_random_bytes(32)):

		self.__key = key
		self.__cipher = AES.new(self.__key)
		self.__hmacKey = hmacKey
		self.__hmac = "There's nothing to HMAC"

	#Provides the HMAC of the plaintext
	def doHmac(self, plaintext):
		sha = SHA256.new()
		theHMAC = HMAC.new(self.__hmacKey, msg = plaintext, digestmod = sha)
		bArrayHMAC = bytearray(theHMAC.digest())
		return  base64.b64encode(bArrayHMAC)

	#Get the hmac
	def getHmac(self):
		return self.__hmac

	#Checks if the given hmac matches our hmac
	def checkHmac(self, theHmac):
		if self.__hmac != theHmac:
			raise IOError("Incorrect MAC!")
		return True

	#Does xor operation 
	#blockOne: the first block
	#blockTWo: the second block
	def __doXOR(self, blockOne, blockTwo):

		b1 = bytearray(blockOne)
		b2 = bytearray(blockTwo)

		return bytearray([b1[i] ^ b2[i] for i in range(len(b1))])

	#Removes the padding from the block
	#text: the data where the padding will be removed
	def __removePad(self, text):
		text = bytearray(text)
		padLength = text[-1] #last element in text is the size of the padding
		textLength = len(text) - padLength #calculates the length of pad by subtracting padLength

		#THIS METHOD DOES NOT DO PADDING VALIDATION AS NEWER VERSIONS OF TLS DOES!!!!!!!!!!

		#Checks in padding is the correct size
		if padLength == 0 or padLength > 16:
			#!!!!!!!!!THIS TELLS THE ADVERSARY WHAT TYPE OF ERROR HAPPENED
			#!!!!!!!!!ADVERSARIES USE THAT INFORMATION IN POODLE
			raise ValueError("Incorrect Padding!")

		#Checks if each expected byte of the padding matches the padLength
		#!!!!!!!!!ADVERSARY EXPLOITS THIS PREDICTABLE PADDING IN POODLE
		for textByte in text[textLength:]:
			if textByte != padLength:
				#!!!!!!!!!THIS TELLS THE ADVERSARY WHAT TYPE OF ERROR HAPPENED
				#!!!!!!!!!ADVERSARIES USE THAT INFORMATION IN POODLE
				raise ValueError("Incorrect Padding!")

		return str(text[:len(text) - padLength])

	#Provides the padding for the block
	#text: the data to be padded
	def __pad(self, text):

		padLength = 16 - (len(text) % 16)
		
		#Adds the padLength into the text xpadLength times
		#!!!!!!!!!ADVERSARY EXPLOITS THE PREDICTABLE PADDING IN POODLE
		return text + bytearray([padLength for _ in range(padLength)])

	#Splits the incoming text into blocks of 16 because of AES and padding will be added if not a multiple of 16.
	#text: the text that will be split into blocks of 16
	def __splitTheBlocks(self, text):

		length = len(text)
		blocks = []
		
		for i in range(length / 16):
			startIdx = i * 16
			endIdx = (i + 1) * 16
			blocks.append(text[startIdx:endIdx])

		return blocks

	#Makes an IV
	def getIV(self):

		return get_random_bytes(16);

	#Encrypts here with AES in CBC Mode
	def encrypt(self, plaintext, iv):

		#Does the HMAC on the plaintext
		self.__hmac = self.doHmac(bytearray(plaintext))

		plaintext = self.__pad( bytearray(plaintext) )
		plainBlocks = self.__splitTheBlocks(plaintext)

		print "\nPlaintext with padding: "#################################################################################################
		print plaintext

		cipherBlocks = []

		#CBC Operation
		for i, pBlock in enumerate(plainBlocks):

			if i == 0:
				xor  = str( self.__doXOR(iv, pBlock) ) #Does first XOR here with IV
			else:
				xor  = str( self.__doXOR(cipherBlocks[i - 1], pBlock) ) #subsequent XORs are done here

			cipherBlocks.append(self.__cipher.encrypt(xor)) #Block encryption happens here

		return base64.b64encode(''.join(cipherBlocks))

	#Decrypts the AES in CBC Mode
	def decrypt(self, ciphertext, iv):

		ciphertext = bytearray(base64.b64decode(ciphertext))
		cipherBlocks = self.__splitTheBlocks(ciphertext)
		
		plainBlocks =[]

		#CBC Operation
		for i, cBlock in enumerate(cipherBlocks):

			dBlock = self.__cipher.decrypt(str(cBlock)) #the decrypted block

			if i == 0:
				xor = str( self.__doXOR(dBlock, iv) )#xor with the iv
			else:
				xor = str( self.__doXOR(dBlock, cipherBlocks[i - 1]) ) #xor in cbc chain

			plainBlocks.append(xor)

		#Remove the padding
		plaintext = self.__removePad(''.join(plainBlocks))

		return plaintext
