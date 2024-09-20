const { mnemonicGenerator, mnemonicToEntropy, validateMnemonic } = require('./mnemonic');
const createKey = require('./key');

function mnemonic(entropy = null) {
    if (entropy != null) {
        return mnemonicGenerator(entropy);
    } if (entropy === null) {
        return mnemonicGenerator();
    }
}

mnemonic.toEntropy = function(mnemonicPhrase) {
    return mnemonicToEntropy(mnemonicPhrase);
}

mnemonic.validate = function(mnemonicPhrase) {
    return validateMnemonic(mnemonicPhrase);
}

async function getKey(mnemonicPhrase, iterations = null) {
    return createKey(mnemonicPhrase, iterations);
}

module.exports = { getKey, mnemonic }
