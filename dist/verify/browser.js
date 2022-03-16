"use strict";
/* import BSON from 'bson';

// stolen from https://stackoverflow.com/a/21797381
function base64ToArrayBuffer(base64: string) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

export default async function verify(str: string, signature: string) {
  // Get string's hash and turn it into base64
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));
  const hashBase64 = window.btoa(String.fromCharCode(...hash));

  const [domain, encrypted] = signature.split('|');

  // Fetch key from the web server
  const pubkeyStr = await fetch(`https://${domain}/public`).then(res => res.text());
  const pubkeyStrNoHF = pubkeyStr.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, '');

  // Import RSA public decryption key
  const pubkey = await crypto.subtle.importKey(
    'pkcs8', base64ToArrayBuffer(pubkeyStrNoHF), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);

  // Decrypt the signature
  const encryptedBinary = base64ToArrayBuffer(encrypted);
  const decryptedBinary: ArrayBuffer = await crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    pubkey,
    encryptedBinary,
  );
  
  // Deserialize the signature
  const decrypted = BSON.deserialize(decryptedBinary);

  // Turn the decrypted hash into base64 in the browser
  const decryptedHash = new Uint8Array(decrypted.hash.buffer);
  const decryptedHashBase64 = window.btoa(String.fromCharCode(...decryptedHash));

  // Check if the signature is valid
  if (decryptedHashBase64 === hashBase64) {
    return [true, decrypted];
  } else {
    return [false, null];
  }
} */
// FROZEN for now as I cannot find a way to decrypt the second layer of encryption in the browser
