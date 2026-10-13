'use strict';

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const app = express();

// Socle volontairement réduit : les protections demandées par le TP restent à ajouter.
app.use(express.json({ limit: '16kb' }));
// Middleware chargeant les cookies envoyés par le client dans req.cookies
app.use(cookieParser())
app.use(helmet({
  hsts: {
    maxAge: 63_072_000, // configuré pour 2 ans
    includeSubDomains: true
  },
  frameguard: {
    action: 'deny' // interdit l'affichage iframe
  },
  noSniff: true
}))

const REFRESH_COOKIE = 'refreshToken'; // Nom du cookie HTTP contenant le refresh token
const REFRESH_OPTION = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax', // strict ou none. None à utiliser si URL front et back différents 
  path: '/api/v1/auth/refresh', // Sur quelle route le navigateur est autorisé à envoyer automatiquement le cookie
  maxAge: 7 * 24 * 60 * 60 * 1000 // Validité du cookie pendant 7 jours
}

// Fonction utilitaire pour charger et valider la longueur minimale d'une clé secrète
function secret(name){
  const value = process.env[name]; // name = refresh, access
  // Garantie que la clé fait au minimum 256 bits (32 octets) pour éviter les clés faibles
  if(!value || Buffer.byteLength(value) < 32)
    throw new Error(`${name} doit contenir au moins 32 octets`)

  return value; // renvoie la clé secrète validée
}

function token(user, type){
  return jwt.sign({
      sub: user.id,
      role: user.role,
      tokenUse: type
    },
    secret(type === 'access' ? 'JWT_ACCESS_SECRET' : 'JWT_REFRESH_SECRET'),
    {
      expiresIn: type === 'access' ? '15m' : '7d',
      algorithm: 'HS256' // Signe avec HMAC-SHA256
    }
  )
}

// Fonction qui permet d'injecter le refresh token
function refreshCookie(res, value){
  res.cookie(
    REFRESH_COOKIE,
    value,
    REFRESH_OPTION
  )
}


const documents = [
  { id: 1, ownerId: 'user-1', title: 'Dossier client', status: 'open' },
  { id: 2, ownerId: 'user-1', title: 'Dossier clôturé', status: 'closed' }
];

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/v1/documents', (req, res) => res.json(documents));

// TODO 1 : ajouter Helmet et cookie-parser.
// TODO 2 : créer l'authentification JWT et la matrice RBAC admin/auditor/user.
// TODO 3 : exposer login/refresh avec un cookie HttpOnly, Secure, SameSite=Strict.
// TODO 4 : chiffrer les coordonnées bancaires avec crypto_service.js.
// TODO 5 : empêcher une modification hors heures ouvrées ou d'un document closed.

const port = process.env.PORT || 3005;
if (require.main === module) {
  app.listen(port, () => console.log(`TP4 démarré sur http://localhost:${port}`));
}

module.exports = app;
