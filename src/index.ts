import env from './env.js';
import dns from 'dns';
import { promises as fsp } from 'fs';
import Fastify from 'fastify';
import FastifyCors from 'fastify-cors';
import { serialize, Binary, Long } from 'bson';
import crypto from 'crypto';

let publicKey: string;
let privateKey: string;

const privateKeyPromise = fsp.readFile(env.privateKeyPath, 'utf8')
  .then((data) => {
    privateKey = data;
  });

// Verify that TXT record is same as public key
dns.resolveTxt(env.domain, async (err, txt) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  
  publicKey = await fsp.readFile(env.publicKeyPath, 'utf8');

  const publicKeyNoSurround = publicKey.replace(/-----BEGIN PUBLIC KEY-----\n|\n-----END PUBLIC KEY-----/g, '');

  if (txt[0].join('') !== publicKeyNoSurround.trim()) {
    console.error('Public key does not match TXT record. Please set your TXT record to the public key (without the header and footer).');
    console.log(`Got:
${txt[0].join('')}
`);
    console.log(`Expected:
${publicKeyNoSurround}`);
    process.exit(1);
  } else {
    // Wait for the private key as well
    await privateKeyPromise;
    fastify.listen(7473, '0.0.0.0', () => {
      console.log(`Listening on 7473`);
    });
  }
});

const fastify = Fastify();

// Allow all origins
fastify.register(FastifyCors, {
  origin: true,
});

// Time sign magic
fastify.post<{ Body: { hash: string } }>('/sign', {
  preValidation: (request, reply, done) => {
    const { hash } = request.body;
    if (!hash) done(new Error('No hash provided.'));
    if (!hash.match(/^[0-9a-f]+$/i)) done(new Error('Provided hash must be a hex string.'));
    else if (hash.length != 64) done(new Error('Provided hash must be 64 bytes long.'));
    else done(undefined);
  }
}, async (request, reply) => {
  // We will assume that the hash is valid
  // It doesn't matter if it's not, user takes the toll
  const hash = request.body.hash;

  // Turn hash into a binary
  const hashBinary = new Binary(Buffer.from(hash, 'hex'));

  // Current time but starting from Feb 8th 2022
  // This is when I asked my girlfriend out
  // EDIT literally 5 seconds later: its actually Jan 25th :facepalm:
  // Shame on me :NotLikeThis:

  // Ironic, isn't it? You're supposed to trust an individual
  // who throws a additional month's worth of seconds
  // in the signed message for personal reasons.

  // I really hope we don't break up.
  const askedHerOut = 1643143800000;
  const now = new Date().getTime();
  const ourEpoch = new Long(now - askedHerOut);

  // Construct the BSON that will serve as signature
  const bson = {
    hash: hashBinary,
    time: ourEpoch,
  };

  // Serialize the BSON
  const bsonBinary = serialize(bson);

  // Encrypt the BSON with the private key
  const encryptedBinary = crypto.privateEncrypt(privateKey, bsonBinary);

  // Turn the encrypted BSON into a base64 string
  const encrypted = encryptedBinary.toString('base64');

  // Concatenate with our domain
  const signed = `${env.domain}|${encrypted}`;

  // Finally, send the time signature to the client
  reply.send(signed);
});

// Public key route
fastify.get('/public', async (request, reply) => {
  // Send the public key
  reply.send(publicKey);
});

export default fastify;
