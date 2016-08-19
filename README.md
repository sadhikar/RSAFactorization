# RSAFactorization
This repository shows 100 RSA public keys generated using bad PRNG's leading to common factors. The core python attack script then finds the keys with common factors, evaluates the both the factors, mints the private key "d" and thus forges a private key certificate file. These private keys can be used to decrypt all the corresponding encrypted text. 


How to run the code:

python factorize.py \<path to the folder with the .pem files\>

ex: python factorize.py ./RSAFiles/


Note: I have added few sleep commands in the script for the purposes of the demo, they are not required for actual algorithm functionality. Will be soon adding a detailed blogpost on this, stay connected here @shrikant86.


---------
