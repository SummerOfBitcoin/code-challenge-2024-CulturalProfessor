# Block Verification Process

This document outlines the process of verifying blocks in a blockchain network, focusing on the verification of transactions with P2WPKH scripts.

## Dependencies
- **secp256k1**: Library for signature verification.
- **crypto-js**: Library for hashing functions.

## Block Verification Steps

### 1. Read Transactions
- Read transactions one by one.
- Generate valid transaction IDs.
- Verify transactions, particularly focusing on P2WPKH scripts.

### 2. SegWit Message Hash Generation
- Generate a message hash of the transaction following the SegWit message hash generation algorithm.

### 3. P2WPKH Script Verification Logic
- Extract signature and public key hex from the witness field.
- Obtain the script pub key hash from the scriptPubKey ASM.
- Generate a new ASM according to P2PKH.
- Pass values for P2PKH stack verification logic (e.g., OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG).
- Use `secp256k1.ecdsaVerify` for signature verification.

### 4. Fee Calculation
- Calculate fees by determining the difference between total input and output values of the transaction.

### 5. Block Formation
- Form the block reward by adding a block subsidy to the total fees.
- Serialize the coinbase transaction and calculate its transaction ID by double SHA256 hashing.
- Generate witness transaction IDs by serializing transactions according to the SegWit serialization algorithm.
- Generate the witness root hash and set the witness reserved value.
- Generate the scriptPubKey for the coinbase transaction.

### 6. Block Header Generation
- Generate a random nonce until it's not less than the given target.
- Combine the block header, serialized coinbase transaction, and valid transaction IDs in the block.

## Conclusion
This process outlines the comprehensive verification logic for P2WPKH scripts in a blockchain network. The steps ensure the integrity and validity of transactions within each block, contributing to the security and reliability of the blockchain network.

## References
- https://learnmeabitcoin.com/
- Discord chats between contributors
- BIPs
