const Web3 = require('web3')
const EthCrypto = require('eth-crypto')
const keythereum = require('keythereum')

function loadAlicePrivateKey () {
  const keyObject = {}
  return new Promise((resolve, reject) => {
    keythereum.recover('123456', keyObject, function (privateKey) {
      resolve(privateKey)
    })
  })
}

function loadBobPrivateKey () {
  // Created from geth account new --datadir ./tmp
  const keyObject = {}

  return new Promise((resolve, reject) => {
    keythereum.recover('123456', keyObject, function (privateKey) {
      resolve(privateKey)
    })
  })
}

// https://ethereum.stackexchange.com/questions/31355/storing-and-passing-encrypted-data-to-another-owner
async function main () {
  const alice = { }
  alice.privateKey = await loadAlicePrivateKey()
  alice.privateKey = alice.privateKey.toString('hex')
  alice.publicKey = EthCrypto.publicKeyByPrivateKey(alice.privateKey)

  const bob = {}
  bob.privateKey = await loadBobPrivateKey()
  bob.privateKey = bob.privateKey.toString('hex')
  bob.publicKey = EthCrypto.publicKeyByPrivateKey(bob.privateKey)
  console.table([alice, bob])

  // https://github.com/pubkey/eth-crypto/blob/master/tutorials/encrypted-message.md
  // Encryption
  const secretMessage = 'plaintext message'
  const signature = EthCrypto.sign(
    alice.privateKey,
    EthCrypto.hash.keccak256(secretMessage)
  )

  const payload = {
    message: secretMessage,
    signature
  }
  const encrypted = await EthCrypto.encryptWithPublicKey(
    bob.publicKey,
    JSON.stringify(payload)
  )
  const encryptedString = EthCrypto.cipher.stringify(encrypted)

  // Decryption
  const encrypedObject = EthCrypto.cipher.parse(encryptedString)
  const decrypted = await EthCrypto.decryptWithPrivateKey(
    bob.privateKey,
    encrypedObject
  )

  const decryptedPayload = JSON.parse(decrypted)
  const senderAddress = EthCrypto.recover(
    decryptedPayload.signature,
    EthCrypto.hash.keccak256(payload.message)
  )

  console.log('got message from', senderAddress, decryptedPayload.message)
}
// main().catch(console.error)

async function test () {
  const web3 = new Web3('http://localhost:8545')

  const privateKey = ''
  const account = await web3.eth.accounts.privateKeyToAccount(privateKey)
  console.log(account)
  const ciphertext = await account.sign('secret data')

  // const ciphertext = await web3.eth.accounts.sign('secret data', privateKey)
  console.log(ciphertext)

  const msg = await web3.eth.accounts.hashMessage('secret data')
  console.log('msg', msg)

  // const ciphertext = await web3.eth.accounts.sign('secret data', privateKey)
  const plaintext = await web3.eth.accounts.recover(ciphertext)
  console.log('get plaintext', plaintext)
}

test().catch(console.error)
