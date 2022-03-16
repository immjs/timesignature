"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bson_1 = require("bson");
const crypto_1 = __importDefault(require("crypto"));
// Stolen from https://gist.github.com/chris-rock/6cac4e422f29c28c9d88
function encrypt(chunk, password) {
    let cipher, result, iv, update, final, authtag;
    // Create an iv
    iv = crypto_1.default.randomBytes(16);
    // Create a new cipher
    cipher = crypto_1.default.createCipheriv('aes-256-gcm', password, iv);
    // Encrypt the chunk
    update = cipher.update(chunk);
    final = cipher.final();
    // Get the authtag
    authtag = cipher.getAuthTag();
    // Create the new chunk
    result = Buffer.concat([authtag, iv, update, final]);
    return result;
}
async function sign(hash, privateKey) {
    // Turn hash into a binary
    const hashBuffer = Buffer.from(hash, 'hex');
    // Current time but starting from Jan 25th 2022
    const askedHerOut = 1643143800000;
    const now = new Date().getTime();
    const ourEpoch = new bson_1.Long(now - askedHerOut);
    // Construct the BSON that will serve as signature
    const bson = {
        time: ourEpoch,
    };
    // Serialize the BSON
    const bsonBinary = (0, bson_1.serialize)(bson);
    // Cipher the BSON with the file hash
    const firstLayerOfEncryption = encrypt(bsonBinary, hashBuffer);
    // Encrypt the BSON with the private key
    const encryptedBinary = crypto_1.default.privateEncrypt(privateKey, firstLayerOfEncryption);
    // Turn the encrypted BSON into a base64 string
    const encrypted = encryptedBinary.toString('base64');
    return encrypted;
}
exports.default = sign;
