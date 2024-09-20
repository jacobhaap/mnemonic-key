const crypto = require('crypto');
const { wordlist } = require('@scure/bip39/wordlists/english');

function generateEntropy() {
    const entropyBuffer = crypto.randomBytes(32);
    const entropy = crypto.createHash('sha256').update(entropyBuffer).digest();
    return entropy;
}

function entropyToMnemonic(entropy) {
    let bits = entropy.slice(0, 154);

    const words = [];
    for (let i = 0; i < bits.length; i += 11) {
        const index = parseInt(bits.slice(i, i + 11), 2);
        words.push(wordlist[index]);
    }
    return words.join(' ');
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

function mnemonicToEntropy(mnemonic) {
    if (!mnemonic) {
        throw new Error(`Parameter 'mnemonic' is required.`)
    }
    const words = mnemonic.split(' ');
    let bits = '';
    words.forEach(word => {
        const index = wordlist.indexOf(word);
        bits += index.toString(2).padStart(11, '0');
    });

    return bits;
}

function validateMnemonic(mnemonic) {
    if (!mnemonic) {
        throw new Error(`Parameter 'mnemonic' is required.`)
    }
    const entropyBits = mnemonicToEntropy(mnemonic);
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
    bits = bits.slice(0, 154);

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
