"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const env_js_1 = __importDefault(require("./env.js"));
const dns_1 = __importDefault(require("dns"));
const fs_1 = require("fs");
const fastify_1 = __importDefault(require("fastify"));
const fastify_cors_1 = __importDefault(require("fastify-cors"));
const sign_js_1 = __importDefault(require("./sign.js"));
const path_1 = __importDefault(require("path"));
let publicKey;
let privateKey;
// Get dirname of the file (es modules)
// const dirname = fileURLToPath(path.dirname(import.meta.url));
const dirname = __dirname;
const toAbsolute = (relpath) => path_1.default.resolve(dirname, '..', relpath);
const privateKeyPromise = fs_1.promises.readFile(toAbsolute(env_js_1.default.privateKeyPath), 'utf8')
    .then((data) => {
    privateKey = data;
});
// Verify that TXT record is same as public key
dns_1.default.resolveTxt(env_js_1.default.domain, async (err, txt) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    publicKey = await fs_1.promises.readFile(toAbsolute(env_js_1.default.publicKeyPath), 'utf8');
    const publicKeyNoSurround = publicKey.replace(/-----BEGIN PUBLIC KEY-----\n|\n-----END PUBLIC KEY-----/g, '');
    if (txt[0].join('') !== publicKeyNoSurround.trim()) {
        console.error('Public key does not match TXT record. Please set your TXT record to the public key (without the header and footer).');
        console.log(`Got:
${txt[0].join('')}
`);
        console.log(`Expected:
${publicKeyNoSurround}`);
        process.exit(1);
    }
    else {
        // Wait for the private key as well
        await privateKeyPromise;
        fastify.listen(7473, '0.0.0.0', () => {
            console.log(`Listening on 7473`);
        });
    }
});
const fastify = (0, fastify_1.default)();
// Allow all origins
fastify.register(fastify_cors_1.default, {
    origin: true,
});
// Time sign magic
fastify.post('/sign', {
    preValidation: (request, reply, done) => {
        const { hash } = request.body;
        if (!hash)
            done(new Error('No hash provided.'));
        if (!hash.match(/^[0-9a-f]+$/i))
            done(new Error('Provided hash must be a hex string.'));
        else if (hash.length != 64)
            done(new Error('Provided hash must be 64 bytes long.'));
        else
            done(undefined);
    }
}, async (request, reply) => {
    const signature = await (0, sign_js_1.default)(request.body.hash, privateKey);
    // Concatenate with our domain
    const signed = `${env_js_1.default.domain}|${signature}`;
    // Finally, send the time signature to the client
    reply.send(signed);
});
// Public key route
fastify.get('/public', async (request, reply) => {
    // Send the public key
    reply.send(publicKey);
});
exports.default = fastify;
