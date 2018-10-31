const {
  encrypt,
  decrypt,
  pbkdf2Hash,
  randomBytes
} = require('./crypto.js')

async function main () {
  const log = logger()
  const password = 'super strong password'
  // Store the keyhash in the same column where we want to protect the data.
  const keyHash = await generateKeyHash(password)
  log.add(['keyHash', keyHash])

  // To derive the user key for encryption/decryption.
  const [,, iterStr, salt,, encryptedUserKey] = keyHash.split('$')
  const iter = Number(iterStr.replace('i=', ''))
  log.add(['salt', salt])
  log.add(['encrypted user key', encryptedUserKey])
  const {hash: passwordDerivedKey} = await pbkdf2Hash(password, Buffer.from(salt, 'base64'), iter)
  const userKey = await decrypt(passwordDerivedKey, encryptedUserKey)
  log.add(['userkey (hex)', userKey.toString('hex')])

  const plaintext = 'hello world!'
  const encryptedData = await encrypt(userKey, plaintext)
  log.add(['encrypted data', encryptedData])

  const decryptedData = await decrypt(userKey, encryptedData)
  log.add(['decrypted data', decryptedData.toString('hex')])

  log.print()

  // Encryption/decryption with ethereum private key. We probably do not need to generate a salt or pbkdf2, since the private key must be unique.
  const privateKey = Buffer.from('', 'hex')
  const e2 = await encrypt(privateKey, 'some secret data')
  console.log(e2)
  const d2 = await decrypt(privateKey, e2)
  console.log(d2.toString('utf8'))
}

async function generateKeyHash (password) {
  const userKey = await randomBytes(32)
  const salt = await randomBytes(32)

  // Number of iterations, the same configuration used by lastpass for server-side hashing.
  // Reference: https://en.wikipedia.org/wiki/PBKDF2
  const iter = 100000
  const {hash: derivedKey, phc} = await pbkdf2Hash(password, salt, iter)
  const encryptedKey = await encrypt(derivedKey, userKey)
  const keyHash = `${phc}$${encryptedKey}`
  return keyHash
}

function logger (data = []) {
  return {
    add: (args) => {
      data.push(args)
    },
    print: () => {
      console.table(data)
    }
  }
}

main().catch(console.error)
