'use strict';
const crypto = require('crypto');

/**
 * 
 * @param {String} data 
 * @param {String} key 
 */
const encrypt = (data, key) => {
    const keyHash = crypto.createHash('sha256').update(key, 'utf8').digest();
    const iv = crypto.randomBytes(16);

    console.log(`iv: [${iv.map(e => e).join(", ")}]`);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyHash, iv);

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    const combinedIvCt = Buffer.concat([iv, encrypted]);

    return combinedIvCt.toString('base64');
}

/**
 * 
 * @param {String} base64EncryptedIVData 
 * @param {String} key 
 */
const decrypt = (base64EncryptedIVData, key) => {
    const keyHash = crypto.createHash('sha256').update(key, 'utf8').digest();
    const cipherTextCombined = Buffer.from(base64EncryptedIVData, 'base64');

    let iv = cipherTextCombined.slice(0, 16);
    let cipherText = cipherTextCombined.slice(iv.length, cipherTextCombined.length);

    console.log(`iv: [${iv.map(e => e).join(", ")}]`);
    let decipher = crypto.createDecipheriv('aes-256-cbc', keyHash, iv);
    let decrypted = decipher.update(cipherText);

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
}

//Ready to use as module
//module.exports = { decrypt, encrypt };

/**
 * Main rutine
 */
(() => {
    // PrivateKey shared over languages (KEEP always server side)
    const key = "J1M6sncXwq1NEWLRbqpp4SixZ6fphrcO";

    // console.log(encrypt("Message", key));
    console.log("Java");
    console.log(decrypt("88/qWM1tDOsU7BhYWxXQH/jTt9fD17ryDSFuGk6YlPY=", key));
    console.log("----");
    console.log("C#");
    console.log(decrypt("vDvzP32YQbNhSNphM7uas95lMVR0vUs2vJCfEQaDzMo=", key));
    console.log("----");
    console.log("NodeJs");
    console.log(decrypt("+nDpo7CTEfsc7I3eOctVNKM57Ai++DzzOlwohKaMU8c=", key));
})();
