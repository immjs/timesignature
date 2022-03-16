import { Long, serialize } from "bson";
import crypto from "crypto";

// Stolen from https://gist.github.com/chris-rock/6cac4e422f29c28c9d88
function encrypt(chunk: Buffer, password: Buffer) {

	let cipher, result, iv, update, final, authtag;

	// Create an iv
	iv = crypto.randomBytes(16);

	// Create a new cipher
	cipher = crypto.createCipheriv('aes-256-gcm', password, iv);

  // Encrypt the chunk
  update = cipher.update(chunk);
  final = cipher.final();

  // Get the authtag
  authtag = cipher.getAuthTag();

	// Create the new chunk
	result = Buffer.concat([authtag, iv, update, final]);

	return result;
}

export default async function sign(hash: string, privateKey: crypto.RsaPrivateKey | crypto.KeyLike) {
  // Turn hash into a binary
  const hashBuffer = Buffer.from(hash, 'hex');

  // Current time but starting from Jan 25th 2022
  const askedHerOut = 1643143800000;
  const now = new Date().getTime();
  const ourEpoch = new Long(now - askedHerOut);

  // Construct the BSON that will serve as signature
  const bson = {
    time: ourEpoch,
  };

  // Serialize the BSON
  const bsonBinary = serialize(bson);

  // Cipher the BSON with the file hash
  const firstLayerOfEncryption = encrypt(bsonBinary, hashBuffer);

  // Encrypt the BSON with the private key
  const encryptedBinary = crypto.privateEncrypt(privateKey, firstLayerOfEncryption);

  // Turn the encrypted BSON into a base64 string
  const encrypted = encryptedBinary.toString('base64');

  return encrypted;
}
