const createKey = require('./key');
const { mnemonicGenerator, mnemonicToEntropy, validateMnemonic } = require('./mnemonic');

async function key(mnemonic) {
    return createKey(mnemonic);
}

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

module.exports = { key, mnemonic }
