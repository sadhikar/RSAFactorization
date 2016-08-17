# RSAFactorization
This repository shows 100 RSA public keys generated using bad PRNG's leading to common factors. The core python attack script then finds the keys with common factors, evaluates the both the factors, mints the private key "d" and thus forges a private key certificate file. These private keys can be used to decrypt all the corresponding encrypted text. 
