"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bson_1 = require("bson");
const crypto_1 = __importDefault(require("crypto"));
const dns_1 = __importDefault(require("dns"));
const node_fetch_1 = __importDefault(require("node-fetch"));
function decrypt(chunk, password) {
    let decipher, result, iv, authtag;
    // Get the authtag: the first 16 bytes
    authtag = chunk.slice(0, 16);
    // Get the iv: the next 16 bytes
    iv = chunk.slice(16, 32);
    // Get the rest
    chunk = chunk.slice(32);
    // Create a decipher
    decipher = crypto_1.default.createDecipheriv('aes-256-gcm', password, iv);
    decipher.setAuthTag(authtag);
    // Actually decrypt it
    result = Buffer.concat([decipher.update(chunk), decipher.final()]);
    return result;
}
async function verify(str, signature, pubkey) {
    let hash;
    if (!(str instanceof Buffer)) {
        // Get string's hash and turn it into base64
        hash = crypto_1.default.createHash('sha256').update(str).digest('hex');
    }
    else {
        hash = str.toString('hex');
    }
    const [domain, encrypted] = signature.split('|');
    if (!pubkey) {
        let pubkeyStr;
        try {
            // Fetch key from the dns
            const pubkeyDns = new Promise((resolve, reject) => {
                dns_1.default.resolveTxt((domain.match(/^[^:]+(\.[^:]+)+(?=:\d+)/g) || ['ts.immjs.dev'])[0], (err, txt) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve(`-----BEGIN PUBLIC KEY-----\n${txt[0].join('')}\n-----END PUBLIC KEY-----`);
                });
            });
            // Fetch key over HTTP(S)
            const pubkeyHttp = (0, node_fetch_1.default)(`${domain}/api/public`).then(res => res.text());
            pubkeyStr = await Promise.any([pubkeyDns, pubkeyHttp]);
        }
        catch (err) {
            return [false, new Error('Failed to fetch public key from DNS and HTTP')];
        }
        try {
            // Import RSA public decryption key
            pubkey = crypto_1.default.createPublicKey(pubkeyStr);
        }
        catch (err) {
            return [false, new Error('Failed to import public key')];
        }
    }
    let decryptedBinary;
    try {
        // Decrypt the signature
        const encryptedBinary = Buffer.from(encrypted, 'base64');
        decryptedBinary = crypto_1.default.publicDecrypt(pubkey, encryptedBinary);
    }
    catch (err) {
        return [false, new Error('Signature\'s content could not be decrypted')];
    }
    let decryptedFirstLayer;
    try {
        // Decrypt the ciphertext with the file hash
        decryptedFirstLayer = decrypt(decryptedBinary, Buffer.from(hash, 'hex'));
    }
    catch (err) {
        return [false, new Error('Signature is not associated with this file')];
    }
    let decrypted;
    try {
        // Deserialize the signature
        decrypted = (0, bson_1.deserialize)(decryptedFirstLayer);
    }
    catch (err) {
        return [false, new Error('Failed to deserialise signature.')];
    }
    return [true, decrypted];
}
exports.default = verify;
