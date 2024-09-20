const { mnemonicGenerator, mnemonicToEntropy, validateMnemonic } = require('./mnemonic');
const createKey = require('./key');

function mnemonic(entropy = null) {
    if (entropy != null) {
        return mnemonicGenerator(entropy);
    } if (entropy === null) {
        return mnemonicGenerator();
    }
}

mnemonic.toEntropy = function(mnemonic) {
    return mnemonicToEntropy(mnemonic);
}

mnemonic.validate = function(mnemonic) {
    return validateMnemonic(mnemonic);
}

async function key(mnemonic) {
    return createKey(mnemonic);
}

module.exports = { key, mnemonic }
