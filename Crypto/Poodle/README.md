Requires Python 2.7
Requires PyCryto library for the AES cipher. The CBC will be implemented in VulnAES with CBC.

The test.py has a formatted way of confirming the the vulnerable method of using AES with CBC functions as expected and that the Poodle vulnerability works.

The VulnAESwithCBC.py implements the vulnerable encryption.

Poodle.py exploits the vulnerability in VulnAESwithCBC.py

The Mathmatical Representation jpeg shows the logic of how the poodle exploit was done
