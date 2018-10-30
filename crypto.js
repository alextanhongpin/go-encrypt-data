const crypto = require('crypto')

async function randomBytes (keyLen = 32) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(keyLen, (err, buf) => {
      // Return the result as bytes buffer.
      err ? reject(err) : resolve(buf)
    })
  })
}

async function encrypt (password, data) {
  const nonceLen = 12
  const nonce = await crypto.randomBytes(nonceLen)
  const cipher = crypto.createCipheriv('aes-256-gcm', password, nonce)

  // Encrypt the given data.
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()])
  const gcmTag = cipher.getAuthTag()

  // Return the encrypted data as base64.
  return Buffer.concat([nonce, encrypted, gcmTag]).toString('base64')
}

async function decrypt (masterKey, data) {
  // The input data is expected to be base64 format. Convert the base64 string
  // back to type Buffer.
  const decoded = Buffer.from(data, 'base64')

  const nonceLen = 12
  const gcmTagLen = 16

  const nonce = decoded.slice(0, nonceLen)
  const ciphertext = decoded.slice(nonceLen, decoded.length - gcmTagLen)
  const authTag = decoded.slice(decoded.length - gcmTagLen)

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, nonce)
  decipher.setAuthTag(authTag)

  // Return the decrypted data as buffer. To get the string representation, use
  // out.toString('utf8').
  return Buffer.concat([
    decipher.update(ciphertext, null, null),
    decipher.final(null)
  ])
}

function pbkdf2Hash (password, salt, iter = 4096, keyLen = 32, digest = 'sha256') {
  if (!password.trim().length) {
    throw new Error('password is required')
  }
  if (!salt.length) {
    throw new Error('salt is required')
  }
  if (salt.length !== 32) {
    throw new Error(`invalid salt length of '${salt.length}'`)
  }
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iter, keyLen, digest, (err, hash) => {
      // Hash is of type Buffer. Buffer.isBuffer(hash) will return
      // true.
      err ? reject(err) : resolve({
        hash,
        salt,
        iter,
        keyLen,
        digest,
        phc: `$pbkdf2-${digest}$i=${iter}$${salt.toString('base64')}$${hash.toString('base64')}`
      })
    })
  })
}

module.exports = {
  randomBytes,
  encrypt,
  decrypt,
  pbkdf2Hash
}
