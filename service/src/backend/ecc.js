var elliptic = require('elliptic');
var BN = require('bn.js');
var crypto = require('crypto');

cv = new elliptic.curve.short({
    a: '0',
    b: 'cd080',
    p: 'c00000000000000000000000000000228000000000000000000000000000018d',
    g: [
        "b044bc1fa42ca2f1d7d88e9dd22b79f0f1277b94804c1d2f7098dceaf01fc4a8",
        "8f2a2d6fe3550e8b6749fc4ad5fa804f941b5eedc115dd54f1b34df2b964dcf6",
    ]
})

const value = crypto.randomBytes(32);
const privateKey = new BN(value.toString('hex'), 16);

const key = crypto
    .createHash('sha512')
    .update("109634600666810143219769876908564842209792799582215620775328394432800030579488")
    .digest('hex')
    .substring(0, 32);
const iv = Buffer.from([0xb3, 0xbf, 0xdf, 0xf7, 0x61, 0x75, 0x3b, 0x06, 0x65, 0x44, 0x79, 0x95, 0x8b, 0x2c, 0xd8, 0x4e]);

// const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
// encryptedData = Buffer.from(cipher.update("Alo123", 'utf8', 'hex') + cipher.final('hex')).toString('base64')
// console.log(encryptedData);

const buff = Buffer.from("Yjg3Y2NlNjRlNWE0OWYwYTk4MTQ4YmMyZGI4Zjk2ZGI=", 'base64');
const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv)
const dec = (decipher.update(buff.toString('utf8'), 'hex', 'utf8') + decipher.final('utf8'))

console.log(dec);
