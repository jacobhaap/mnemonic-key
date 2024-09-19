const crypto = require('crypto');
const { mnemonicToEntropy, validateMnemonic } = require('./mnemonic');
const { base58 } = require('@scure/base');

async function createKey(mnemonic) {
    const wordArray = mnemonic.split(' ');
    if (wordArray.length !== 14) {
        throw new Error('Exactly 14 words are required');
    }

    try {
        const validate = validateMnemonic(mnemonic);
        if (validate) {
            const entropy = mnemonicToEntropy(mnemonic);
            let keySeed = entropy.slice(-77);
            let salt = entropy.slice(0, 77);

            keySeed = crypto.createHash('sha256').update(keySeed).digest();
            salt = crypto.createHash('sha256').update(salt).digest();
            salt = base58.encode(Buffer.from(salt, 'hex'));

            let cryptographicKey = crypto.pbkdf2Sync(keySeed, salt, 210000, 32, 'sha512');
            return cryptographicKey.toString('hex');
        }
    } catch (error) {
        throw error;
    }
}

module.exports = createKey;
