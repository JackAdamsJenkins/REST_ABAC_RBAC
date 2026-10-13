'use strict';

const crypto = require('node:crypto')
const ALGORIHTM = 'aes-256-gcm';
const IV_BYTES = 16;

function encryptionKey(){

}

function decodeBase64(){

}

// À compléter : AES-256-GCM, clé de 32 octets Base64, IV aléatoire de 16 octets
// et vérification du tag d'authentification au déchiffrement.
function encrypt(plaintext) {
  throw new Error('TODO: implémenter encrypt() avec AES-256-GCM');
}

function decrypt(envelope) {
  throw new Error('TODO: implémenter decrypt() et vérifier le tag GCM');
}

module.exports = { encrypt, decrypt };
