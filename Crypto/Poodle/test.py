from VulnAESwithCBC import AESwithCBC
from Poodle import Poodle
import base64

if __name__ == "__main__":

	
	####ENCRYPTION, DECRYPTION, AND HMAC CHECK################

	cipher = AESwithCBC()
	iv = cipher.getIV()

	#Plaintext
	plaintext = "This is a secret string that no one should see before Christmas"
	print len(plaintext)
	print "Plaintext: " 
	print plaintext

	#Encrypt
	ciphertext = cipher.encrypt(plaintext, iv)
	print "\nCiphertext: "
	print ciphertext
	c = bytearray(base64.b64decode(ciphertext))
	print len(c)

	#Decrypt
	decryptedtext = cipher.decrypt(ciphertext, iv)
	print "\nDecryptedtext: "
	print decryptedtext
	
	#Check if decrypted correct
	decryptedHash = cipher.doHmac(decryptedtext)
	print "HMAC match: " + str(cipher.checkHmac(decryptedHash))

	
	print "\n#########################################"
	

	####ENCRYPTION AND DECRYPTION CHECK################
	print "\nPOODLE EXPLOIT STARTING...........................\n"
	p = Poodle(ciphertext, cipher, iv)
	poodletext = p.exploit()
	
	if(poodletext == plaintext):
		print "SUCCESS!!!"
		print "Poodletext(" + poodletext + ") and plaintext(" + plaintext + ") match! EXPLOIT COMPLETED"
	else:
		print "\nEXPLOIT FAILED :("

	print "\nPOODLE EXPLOIT COMPLETED!!!!!!!!!"
	