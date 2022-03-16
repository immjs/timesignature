import env from './env.js';
import dns from 'dns';
import { promises as fsp } from 'fs';
import Fastify from 'fastify';
import FastifyCors from 'fastify-cors';
import sign from './sign.js';
import verify from './verify/node.js';
import path from 'path';
import crypto from 'crypto';

let publicKey: string;
let privateKey: string;

// Get dirname of the file (es modules)
// const dirname = fileURLToPath(path.dirname(import.meta.url));
const dirname = __dirname;
const toAbsolute = (relpath: string) => path.resolve(dirname, '..', relpath)

const privateKeyPromise = fsp.readFile(toAbsolute(env.privateKeyPath), 'utf8')
  .then((data) => {
    privateKey = data;
  });

// Verify that TXT record is same as public key
dns.resolveTxt(env.domain, async (err, txt) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  
  publicKey = await fsp.readFile(toAbsolute(env.publicKeyPath), 'utf8');

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
  const signature = await sign(request.body.hash, privateKey);

  // Concatenate with our domain
  const signed = `${env.domain}|${signature}`;

  // Finally, send the time signature to the client
  reply.send(signed);
});

fastify.post<{ Body: { hash: string, signature: string } }>('/verify', {
  preValidation: (request, reply, done) => {
    const { hash, signature } = request.body;
    if (!hash) done(new Error('No hash provided.'));
    if (!hash.match(/^[0-9a-f]+$/i)) done(new Error('Provided hash must be a hex string.'));
    else if (hash.length != 64) done(new Error('Provided hash must be 64 bytes long.'));
    else if (!signature) done(new Error('No signature provided.'));
    else if (!signature.match(/^.+\|[a-zA-Z0-9+/]+=*$/)) done(new Error('Invalid signature format.'));
    else done(undefined);
  }
}, async (request, reply) => {
  const { hash, signature } = request.body;
  // Convert hash to buffer
  const hashBuffer = Buffer.from(hash, 'hex');

  const [ isValid, signatureData ] = await verify(hashBuffer, signature, publicKey);

  if (!isValid) return reply.code(401).send(`Invalid signature: ${signatureData.message}`);
  reply.send(signatureData);
});

// Public key route
fastify.get('/public', async (request, reply) => {
  // Send the public key
  reply.send(publicKey);
});

export default fastify;
