'use strict';

const crypto = require('node:crypto')
const ALGORIHTM = 'aes-256-gcm';
const IV_BYTES = 16;

// Fonction chargeant et validant la clé symétrique depuis les variables d'environnement
// La clé reste hors du code et sa taille est contrôlée avant tout usage
function encryptionKey(){
  const encoded = process.env.ENCRYPTION_KEY_BASE64;
  if(!encoded) throw new Error('ENCRYPTION_KEY_BASE64 est requis');
  // Convertit une clé stockée sous forme de texte (encodée en base64) en son format d'origine :
  // Une suite brute d'octets (Buffer binaire)
  const key = Buffer.from(encoded, 'base64');
  if(key.length !== 32 || key.toString('base64') !== encoded)
    throw new Error('ENCRYPTION_KEY_BASE64 doit encoder exactement 32 octets');

  return key; // Retourne le Buffer contenant la clé binaire de 32 octets
}
// Fonction utilitaire pour valider et décoder de manière stricte une chaine base64
function decodeBase64(value, field){
  if(typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    throw new TypeError(`${field} Base64 invalide`) // Rejette l'entrée si ce n'est pas une chaîne base64 valide
  const decoded = Buffer.from(value, 'base64'); // décode la chaîne base64 vers un Buffer
  // buffer en node.js c'est un espace mémoire qui stocke une suite brute d'octets (des nombres de 0 à 255)
  // plutôt que du texte
  if(decoded.toString('base64') !== value)
    throw new TypeError(`${field} Base64 invalide`)

  return decoded; //Renvoie le Buffer binaire décodé
}

// À compléter : AES-256-GCM, clé de 32 octets Base64, IV aléatoire de 16 octets
// et vérification du tag d'authentification au déchiffrement.
function encrypt(plaintext) {
  if(typeof plaintext !== 'string') throw new TypeError('Le texte doit être une chaine')
    const iv = crypto.randomBytes(IV_BYTES); // Génère un vecteur d'initialisation aléatoire et unique de 16 octets
    const cipher = crypto.createCipheriv(ALGORIHTM, encryptionKey(), iv);
    const cipherText = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    return {
      algorithm: ALGORIHTM,
      iv: iv.toString('base64'),
      cipherText: cipherText.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64')
    }
}

function decrypt(envelope) {
  if(!envelope || envelope.algorithm !== ALGORIHTM)
    throw new TypeError('Enveloppe non prise en charge');
  const iv = decodeBase64(envelope.iv, 'iv');
  const cipherText = decodeBase64(envelope.cipherText, 'ciphertext');
  const authTag = decodeBase64(envelope.authTag, 'authTag')
  if(iv.length !== IV_BYTES || authTag.length !== 16)
    throw new TypeError('Enveloppe mal formée')

  const decipher = crypto.createDecipheriv(ALGORIHTM, encryptionKey(), iv);
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8')
}

module.exports = { encrypt, decrypt, encryptionKey };
