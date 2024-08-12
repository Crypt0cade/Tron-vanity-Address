# Tron-vanity-Address
Tron Vanity Address Generator

Basic implementation of Vanity address, ideal for few characters.

1-install libraries

for (keccak256)

2- cmake , make

3- compile

 g++ vanitytron.cpp -o vanitytron.exe -L/YOUR/PATH -lsecp256k1 -lcrypto -lssl -lbase58 -lkeccak256

**usage:** 

./vanitytron "-s: Search for strings at the beginning (excluding prefix)"

./vanitytron "-e: Search for strings at the end of the address"

./vanitytron "-c: Case-sensitive search"

**example:**

./vanitytron -s ron

//

Searching for vanity Tron address...

Found vanity address: TRon8WRMj2NWpmcGFppC7d3zTL1uQEEgYu

Private key: c89cce35477f7b6fdd32bef1b7912d100ac065d64813ee2bd8d13bcb33e48d93

Results saved to vanity_addresses.txt

Eureka!//





1 coffee Address:

**TXXxxku8cSRbWiMzVtod17wBtwadt4giGS**

