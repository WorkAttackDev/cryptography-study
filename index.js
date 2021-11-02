// hashing function

const { log } = require('console');
const {
  createHash,
  scryptSync,
  randomBytes,
  timingSafeEqual,
  createHmac,
  createCipheriv,
  createDecipheriv,
  getCiphers,
  generateKeyPairSync,
} = require('crypto');

// const hash = (input) => createHash('sha256').update(input).digest('hex');

// const password = 'Denilson1234';
// const hashedPass = hash(password);

// const password2 = 'Denilson1234';
// const hashedPass2 = hash(password2);

// const match = hashedPass === hashedPass2;

// log(match ? '✅   good password' : '❌   password not match');

// // hashing with salt

// const users = [];

// const signup = (email, password) => {
//   const salt = randomBytes(16).toString('hex');
//   const hashedPassword = scryptSync(password, salt, 64).toString('hex');
//   const user = { email, password: `${salt}:${hashedPassword}` };
//   users.push(user);
//   return user;
// };

// const login = (email, password) => {
//   const user = users.find((_v) => _v.email === email);
//   if (!user) throw new Error('user not found');

//   const [salt, key] = user.password.split(':');
//   const hashedBuffer = scryptSync(password, salt, 64);

//   const keyBuffer = Buffer.from(key, 'hex');
//   const match = timingSafeEqual(hashedBuffer, keyBuffer);
//   if (match) return user;

//   return 'Icorrect password';
// };

// // Hashing with Hmac

// const secretKey = 'My super secret key 👊🏿';
// const message = 'Thats a message';

// const hmac = createHmac('sha256', secretKey).update(message).digest('hex');

// log(hmac);

// symmetric encryption

// const message = 'Never forget that';

// const cipherKey = randomBytes(32);
// const cipherIv = randomBytes(16);

// const cipher = createCipheriv('aes256', cipherKey, cipherIv);

// const encryptedMessage =
//   cipher.update(message, 'utf8', 'hex') + cipher.final('hex');

// //* Decipher

// const decipher = createDecipheriv('aes256', cipherKey, cipherIv);

// const decryptedMessage =
//   decipher.update(encryptedMessage, 'hex', 'utf8') + decipher.final('utf8');

// log('encrypted message:', encryptedMessage);
// log('decrypted message:', decryptedMessage);

// generating private and publick key

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  publicKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphase: 'create experience',
  },
});

log('private key:', privateKey);
log('public key:', publicKey);
