const crypto = require('crypto');
const { bip39 } = require('@iacobus/bip39')
const { wordlist } = require('@iacobus/bip39/wordlists/english');

function generateEntropy() {
    const entropyBuffer = crypto.randomBytes(32);
    const entropy = crypto.createHash('sha256').update(entropyBuffer).digest();
    return entropy;
}

function entropyToMnemonic(entropy) {
    const bits = entropy.slice(0, 154);
    const result = bip39.ext.toMnemonic(wordlist, bits);

    return result;
}

function createChecksum(bits) {
    const truncatedBits = bits.slice(0, 149);
    const hash = crypto.createHash('sha256').update(Buffer.from(truncatedBits, 'binary')).digest();
    const checksumBits = Array.from(hash)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('')
        .slice(0, 5);
    const checksummedBits = truncatedBits + checksumBits;

    return checksummedBits;
}

function verifyChecksum(bits) {
    if (!bits) {
        throw new Error(`Parameter 'bits' is required.`)
    }
    const entropyBits = bits.slice(0, 149);
    const checksum = bits.slice(149);
    const hash = crypto.createHash('sha256').update(Buffer.from(entropyBits, 'binary')).digest();
    const calculatedChecksum = Array.from(hash)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('')
        .slice(0, 5);

    return checksum === calculatedChecksum;
}

function mnemonicToEntropy(mnemonicPhrase) {
    if (!mnemonicPhrase) {
        throw new Error(`Parameter 'mnemonicPhrase' is required.`)
    }
    const result = bip39.ent.toEntropy(wordlist, mnemonicPhrase);

    return result;
}

function validateMnemonic(mnemonicPhrase) {
    if (!mnemonicPhrase) {
        throw new Error(`Parameter 'mnemonicPhrase' is required.`)
    }
    const wordArray = mnemonicPhrase.split(' ');
    if (wordArray.length !== 14) {
        throw new Error('Exactly 14 words are required');
    }
    const entropyBits = mnemonicToEntropy(mnemonicPhrase);
    const validated = verifyChecksum(entropyBits);
    if (validated === true) {
        return validated;
    } else {
        throw new Error(`Mnemonic failed validation.`);
    }
}

function mnemonicGenerator(providedEntropy = null) {
    let entropy;
    
    if (providedEntropy) {
        if (!/^[0-9a-fA-F]+$/.test(providedEntropy) || providedEntropy.length < 39) {
            throw new Error('Invalid entropy: must provide at least 39 hex characters.');
        }
        entropy = Buffer.from(providedEntropy, 'hex');
    } else {
        entropy = generateEntropy();
    }

    let bits = Array.from(entropy)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('');
    bits = bits.slice(0, 149);

    const checksummedBits = createChecksum(bits);
    const mnemonic = entropyToMnemonic(checksummedBits);
    const verify = verifyChecksum(checksummedBits);
    if (verify === true) {
        return mnemonic;
    } else {
        throw new Error(`Invalid Mnemonic Generated.`);
    }
}

module.exports = { mnemonicGenerator, mnemonicToEntropy, validateMnemonic };
