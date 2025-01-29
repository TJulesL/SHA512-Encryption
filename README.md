# SHA512-Encryption
Encryption with SHA3-512 making use of a 1024 bit Feistel Network in python

## Description

This is a project that uses Feistel network and the SHA3-512 hash function to encrypt data. You may ask yourself what a one-way hash function would be able to do in a two-way encryption algorithm. 

A feistel network is designed so that you have a function *f* that does not have to be reversible. There are many encryption algorithms that still use the feistel cipher to this day like DES (obsolete due to small key size), Twofish, Blowfish etc.  One good example of a non reversible algorithm is a hash function. Here is an example of a feistel network :

![](https://upload.wikimedia.org/wikipedia/commons/thumb/f/fa/Feistel_cipher_diagram_en.svg/410px-Feistel_cipher_diagram_en.svg.png)

Kn being the round keys, L and R being the left and right half of the block and F being the feistel function which we talked about. So now that we know that you can use SHA3-512 as a f function still being able to reverse it you get the general idea of this project.


In this project we use the PBKDF2 key derivation with SHA3-512 function to generate round keys and the SHA3-512 function itself again as the F function. I made it so that each side is 512 bits so the total block size is 1024 bits (128 bytes). Since the SHA3-512 function is so called "Quantum resistant" Theoretically this encryption algorithm should be safe against quantum computer attacks except brute force ofcourse. 


Finally i want to make it clear that this is a project that is made for fun and most likely isn't safe against for example timing attacks so dont expect this encryption algorithm to be super safe. Theoretically it should be safe enough for proper encryption however i haven't tested it yet so i would strongly advice against using it for that purpose.
## 




## Usage/Examples
Clone the project

```bash
git clone https://github.com/TJulesL/SHA512-Encryption.git
```

Go to the project directory

```bash
cd SHA512-Encryption
```

Install dependencies for hashing 
```bash
pip install cryptography
```

Execute the file

```bash
python3 SHA512-encryption.py
```

## Features

- Multithreading
- SHA3-512 encryption


## Sources
- [Feistel network on wikipedia](https://en.wikipedia.org/wiki/Feistel_network)
## Authors

- [@TJulesL](https://www.github.com/TJulesL)


## FAQ


#### Where is the decryption?

The decryption function is not implemented however if you want to do it yourself it is very easy to do since you only need to reverse the [feistel network](https://en.wikipedia.org/wiki/Feistel_network). At the time of writing this i will not implement it in the future since the project was more of a way to show how the feistel network works, and if really needed people can implement the decryption function themselves pretty easily building on this repository's code.

#### Is this code safe to use for encrypting sensitive data?

Short answer : No, not at all

Long answer : The cipher in itself is theoretically safe to use for encryption however i strongly doubt it. Also since this code uses the ECB mode it is not safe for encrypting data because it will reveal patterns in some data. There are other [modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) however they are not coded.

