// Converting buffer to other format (base64, hex)
// buf.toString('hex')
// To convert back
// Buffer.from(hex, 'hex')
// Buffer.from(base64, 'base64')

const crypto = require('crypto')

async function main () {
  // Generating random bytes with keyLen 32.
  const userKey = await randomBytes(32)
  console.log('userKey:', userKey.toString('hex'))

  const salt = await randomBytes(32)
  console.log('salt:hex', salt.toString('hex'))
  console.log('salt:base64', salt.toString('base64'))

  const iter = 4096
  const password = Buffer.from('hello world')
  const keyLen = 32
  const digest = 'sha256'

  const derivedKey = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iter, keyLen, digest, (err, derivedKey) => {
      err ? reject(err) : resolve(derivedKey)
    })
  })

  console.log('password derivedKey:', derivedKey.toString('base64'))
  const phcPbkdf2 = `pbkdf2-${digest}$i=${iter}$${salt.toString('base64')}$${derivedKey.toString('base64')}`
  console.log('phcPbkdf2:', phcPbkdf2)
  // Use the derivedKey to encrypt the user key.
  const encryptedUserKey = encrypt(derivedKey, userKey)
  console.log('encryptedUserKey', encryptedUserKey)

  const keyHash = `${encryptedUserKey}$${salt.toString('base64')}`
  console.log('keyHash', keyHash)
  console.log(decrypt(derivedKey, encryptedUserKey) === userKey)

  const encryptedData = encrypt(userKey, 'hello world!')
  console.log('encrypted data', encryptedData)

  const decryptedData = decrypt(userKey, encryptedData)
  console.log('decrypted data', decryptedData)

  // ==========================================================================
  // Attempt to decrypt the data.
  // ==========================================================================
  const keyHash2 = 'd0GQjMlKg7xKvO6ImaZ6O2wxjqQlfbks5BH4joPmdd7KnOUqELgWxrqwH1jBo21+o3zYjXY7nLG9Lqrc$39/vKV+bUm8lWcq0G094FWqKgEt51exMUF0Jqfferdo='
  const [encryptedUserKey2, salt2] = keyHash2.split('$').map((i) => Buffer.from(i, 'base64').toString('hex'))
  console.log('salt asciii', salt2)
  console.log('encrypted user', encryptedUserKey2)
  const derivedKey2 = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, Buffer.from(salt2), iter, keyLen, digest, (err, derivedKey) => {
      err ? reject(err) : resolve(derivedKey)
    })
  })
  console.log('userkey', Buffer.from(encryptedUserKey2).toString('hex'))
  console.log('salt', Buffer.from(salt2).toString('hex'), salt2)

  const decryptedUserKey2 = decrypt(derivedKey2, encryptedUserKey2)
  console.log('decryptedUserKey2', decryptedUserKey2)
}

main().catch(console.error)

async function randomBytes (keyLen = 32) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(32, (err, buf) => {
      err ? reject(err) : resolve(buf)
    })
  })
}

// https://gist.github.com/AndiDittrich/4629e7db04819244e843
function encrypt (password, data) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', password, iv)

  // Encrypt the given data.
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()])

  // Extract the auth tag. len=16
  const tag = cipher.getAuthTag()

  return Buffer.concat([iv, encrypted, tag]).toString('base64')
}

function decrypt (password, data) {
  const buf = Buffer.from(data, 'base64')
  const nonceSize = 12
  const tagSize = 16
  const iv = buf.slice(0, nonceSize)
  const encryptedData = buf.slice(nonceSize, buf.length - tagSize)
  const tag = buf.slice(buf.length - tagSize)
  const decipher = crypto.createDecipheriv('aes-256-gcm', password, iv)
  decipher.setAuthTag(tag)
  return decipher.update(encryptedData, 'binary', 'utf8') + decipher.final('utf8')
}
