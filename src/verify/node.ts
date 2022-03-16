import { deserialize } from 'bson';
import crypto from 'crypto';
import dns from 'dns';
import fetch from 'node-fetch';

function decrypt(chunk: Buffer, password: Buffer) {
  let decipher, result, iv, authtag;

	// Get the authtag: the first 16 bytes
	authtag = chunk.slice(0, 16);

	// Get the iv: the next 16 bytes
	iv = chunk.slice(16, 32);

	// Get the rest
	chunk = chunk.slice(32);

	// Create a decipher
	decipher = crypto.createDecipheriv('aes-256-gcm', password, iv);

  decipher.setAuthTag(authtag);

	// Actually decrypt it
	result = Buffer.concat([decipher.update(chunk), decipher.final()]);

	return result;
}

export default async function verify(
  str: string | Buffer,
  signature: string,
  pubkey?: crypto.KeyLike,
): Promise<[true, Record<string, any>] | [false, Error]> {
  let hash;
  if (!(str instanceof Buffer)) {
    // Get string's hash and turn it into base64
    hash = crypto.createHash('sha256').update(str).digest('hex');
  } else {
    hash = str.toString('hex');
  }

  const [domain, encrypted] = signature.split('|');

  if (!pubkey) {
    let pubkeyStr;
    try {
      // Fetch key from the dns
      const pubkeyDns: Promise<string> = new Promise((resolve, reject) => {
        dns.resolveTxt(domain, (err, txt) => {
          if (err) {
            reject(err);
            return;
          }

          resolve(`-----BEGIN PUBLIC KEY-----\n${txt[0].join('')}\n-----END PUBLIC KEY-----`);
        });
      });
      // Fetch key over HTTP(S)
      const pubkeyHttp: Promise<string> = fetch(`https://${domain}/public`).then(res => res.text());
      pubkeyStr = await Promise.any([pubkeyDns, pubkeyHttp]);
    } catch (err) {
      return [false, new Error('Failed to fetch public key from DNS and HTTP')];
    }
    try {
      // Import RSA public decryption key
      pubkey = crypto.createPublicKey(pubkeyStr);
    } catch (err) {
      return [false, new Error('Failed to import public key')];
    }
  }

  let decryptedBinary;
  try {
    // Decrypt the signature
    const encryptedBinary = Buffer.from(encrypted, 'base64');
    decryptedBinary = crypto.publicDecrypt(pubkey, encryptedBinary);
  } catch (err) {
    return [false, new Error('Signature\'s content could not be decrypted')];
  }

  let decryptedFirstLayer;
  try {
    // Decrypt the ciphertext with the file hash
    decryptedFirstLayer = decrypt(decryptedBinary, Buffer.from(hash, 'hex'));
  } catch (err) {
    return [false, new Error('Signature is not associated with this file')];
  }

  let decrypted;
  try {
    // Deserialize the signature
    decrypted = deserialize(decryptedFirstLayer);
  } catch (err) {
    return [false, new Error('Failed to deserialise signature.')];
  }
  return [true, decrypted];
}
