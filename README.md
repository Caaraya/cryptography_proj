# cryptography_proj
Security engineering, cryptography assignment with client and server code.

Key generation
http://esus.com/programmatically-generating-public-private-key/

Crypto library
https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html

--Compile server and client in directory 'cryptography_proj'--
javac ChatServer.java ChatUtils.java Integrity.java
javac ChatClient.java ChatUtils.java Integrity.java


--Run server and client in parent directory of 'cryptography_proj'--
java cryptography_proj.ChatServer (port number) (cia option)
java cryptography_proj.ChatClient localhost (port number) (cia option)



Asymmetric encryption algorithm : RSA

Symmetric encryption algorithm : AES with CBC

Password encryption : md5sum
