# Mnemonic Key
![NPM Version](https://img.shields.io/npm/v/mnemonic-key) ![NPM License](https://img.shields.io/npm/l/mnemonic-key) ![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/mnemonic-key)

> 14-word Mnemonic Phrases for deterministic Cryptographic Key derivation.

Mnemonic Key is an implementation of 14-word Mnemonic Phrases for deterministic Cryptographic Key derivation, using the **BIP39 English wordlist** for mnemonics, and the **PBKDF2 function** for key derivation. To get started, install the library:
```bash
npm install mnemonic-key
```
This library consists of two functions: **mnemonic** and **getKey**. The mnemonic function also has two available methods: **toEntropy**, and **validate**. These functions are used in the creation of Mnemonic Phrases, Cryptographic Keys, converting a phrase back to its checksummed entropy, and validating a Mnemonic Phrase.

**Important Note:** While this library does use the BIP39 English wordlist, and map entropy to mnemonics based on [the BIP39 standard](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)'s guidelines using **@iacobus/bip39**, the mnemonic-key library does not produce phrases in compliance with the standard, for the following reasons:
 - Mnemonic Phrases of 14 words are based on 149 bits of initial entropy + a 5 bit checksum. [BIP39 specifies](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic) that initial entropy must be a multiple of 32, which 149 is not.
 - The reason 14-word mnemonics are used is to establish a clear distinction that the keys they represent are not seeds/private keys for cryptocurrency wallets. Since 14 words is outside the scope of BIP39, it makes for a safe and distinct choice in an application unrelated to cryptocurrency, away from the most commonly used 12, 18, and 24-word phrases.
 - The key derivation is a separate process from [key derivation under BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed). Compared to the BIP39 process[^1], this library also uses the **PBKDF2 function** for key derivation, but uses the entropy of the mnemonic rather than the mnemonic itself, along with hashing of the entropy and base58 encoding in the key derivation process. See the section [Cryptographic Keys](#cryptographic-keys) for more information.

## Mnemonic Phrases
Mnemonic Phrases are generated using the `mnemonic` function. This function takes 154 bits of entropy to obtain a mnemonic via the `toMnemonic` [function](https://www.npmjs.com/package/@iacobus/bip39#tomnemonic) and the [BIP39 English wordlist](https://www.npmjs.com/package/@iacobus/bip39#wordlists) provided by **@iacobus/bip39**.

```js
mnemonic(entropy);
```
This function expects a single optional `entropy` parameter, expecting at least 154 bits of entropy (suppled in Hexadecimal) when provided. Otherwise, entropy is generated internally with the [Node.js **Crypto** module's](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback) `crypto.randomBytes();` function. The entropy is truncated to 149 bits, and a checksum is generated by taking the first 5 bits of the SHA-256 hash of the truncated entropy. This checksum is then appended to the end of the truncated entropy to produce a total of 154 bits entropy + checksum.

*Example use with "entropy" provided:*
```js
const { mnemonic } = require('mnemonic-key');

// 200 Bits of entropy in Hex
const entropy = "22496368206D75737320726175732122202D204A616E6E6573";

const mnemonicPhrase = mnemonic(entropy);
console.log("Mnemonic Phrase:", mnemonicPhrase);

// Function Output 
// Mnemonic Phrase: car enrich sure dolphin struggle rifle smart atom gesture process sign dust actress mystery

```
Before the function returns the mnemonic, the Mnemonic Phrase is validated internally via verification of the checksum. If validation is passed, the function returns a 14-word Mnemonic Phrase derived from the generated or provided entropy in its output.

### `toEntropy` Method
This method of the **mnemonic** function allows the checksummed entropy used during the generation of a Mnemonic Phrase to be obtained, using the `toEntropy` [function from **@iacobus/bip39**](https://www.npmjs.com/package/@iacobus/bip39#toentropy). This method expects a single `mnemonicPhrase` parameter be provided, which must contain a 14 word Mnemonic Phrase.
```js
mnemonic.toEntropy(mnemonicPhrase);
```

*Example Use:*
```js
const { mnemonic } = require('mnemonic-key');

// Mnemonic Phrase
const mnemonicPhrase = "car enrich sure dolphin struggle rifle smart atom gesture process sign dust actress mystery"

const entropy = mnemonic.toEntropy(mnemonicPhrase);
console.log("Entropy from Mnemonic:", entropy);

// Function Output 
// Entropy from Mnemonic: 0010001001001001011000110110100000100000011011010111010101110011011100110010000001110010011000010111010101110011001000010010001000100000001011010010010011

```
This function returns the checksummed entropy for the provided Mnemonic Phrase in its output.

### `validate` Method
This method of the **mnemonic** function allows for a Mnemonic Phrase to be validated. This works by first obtaining the checksummed entropy of a given Mnemonic Phrase, then verifying the checksum via the same checksum verification function used for internal validation during Mnemonic Phrase generation. This method expects a single `mnemonicPhrase` parameter be provided, which must contain a 14 word Mnemonic Phrase.
```js
mnemonic.validate(mnemonicPhrase);
```

*Example Use:*
```js
const { mnemonic } = require('mnemonic-key');

// Mnemonic Phrase
const mnemonicPhrase = "car enrich sure dolphin struggle rifle smart atom gesture process sign dust actress mystery"

const validation = mnemonic.validate(mnemonicPhrase);
console.log("Valid Mnemonic:", validation);

// Function Output 
// Valid Mnemonic: true

```
This function returns a true or false value in its output, returning true if the Mnemonic Phrase passed validation, and returning false if validation failed.

## Cryptographic Keys
Cryptographic Keys are generated using the **getKey** function. Keys are derived from Mnemonic Phrases using the **PBKDF2** ([Password-Based Key Derivation Function 2](https://nodejs.org/api/crypto.html#cryptopbkdf2syncpassword-salt-iterations-keylen-digest)) synchronous key derivation function.
```js
crypto.pbkdf2Sync(password, salt, iterations, keylen, digest);
```
In this setup, the provided Mnemonic Phrase is converted back to a string of 154 bits (the checksummed entropy), where a SHA-256 hash of the last 77 bits is taken and supplied as the `password`, and a SHA-256 hash of the first 77 bits is taken and encoded in [base58 using **@scure/base**](https://www.npmjs.com/package/@scure/base) to derive a `salt`. A number of `iterations` is provided, the requested byte length of the key (`keylen`) is set to *32*, and the `digest` is set to *SHA512*.
```js
getKey(mnemonicPhrase, iterations);
```
This function expects a `mnemonicPhrase` parameter, which should be a 14-word Mnemonic Phrase. An optional `iterations` parameter may also be provided, allowing the number of iterations to be specified. If no number is provided, a default of *210,000* will be used, based on the [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) for **PBKDF2-HMAC-SHA512**.

*Example use without "iterations" provided:*
```js
const { getKey } = require('mnemonic-key');

// Mnemonic Phrase
const mnemonicPhrase = "car enrich sure dolphin struggle rifle smart atom gesture process sign dust actress mystery"

getKey(mnemonicPhrase).then((key) => {
    console.log("Cryptographic Key:", key);
  });

// Function Output 
// Cryptographic Key: bc8266145c9c1c1e056225bab6460bc77789a826e455fa9c7d604b99043991d1

```
This function returns a Cryptographic Key, derived from the provided Mnemonic Phrase, in its output.

[^1]: Citing BIP39 *from mnemonic to seed*, "To create a binary seed from the mnemonic, we use the PBKDF2 function with a mnemonic sentence (in UTF-8 NFKD) used as the password and the string "mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt. The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random function. The length of the derived key is 512 bits (= 64 bytes)."
