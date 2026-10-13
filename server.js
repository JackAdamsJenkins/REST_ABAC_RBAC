'use strict';

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const bcrypt = require('bcryptjs');
const { encrypt, decrypt, encryptionKey } = require('./crypto_service');
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
const REFRESH_CLEAR_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax', // strict ou none. None à utiliser si URL front et back différents 
  path: '/api/v1/auth/refresh', // Sur quelle route le navigateur est autorisé à envoyer automatiquement le cookie
}

// Matrice des permissions associée à chaque rôle utilisateur (contrôle d'accès RBAC)
const PERMISSIONS = {
  admin: ['bank:create', 'bank:read:any', 'document:update:any'], // permissions globale sur banques et documents
  auditor: ['bank:read:any'], // Rôle auditeur : persmission de lecture sur tous les comptes bancaires uniquement
  user: ['bank:create', 'bank:read:own', 'document:update:own'] // Permissions limitées à ses propres ressources
}

function requirePermission(...needed){
  // Vérifie si le rôle de l'utilisateur possède au moins une des permissions requises
  return (req, res, next) => needed.some(permission => PERMISSIONS[req.user.role].includes(permission)) 
    ? next() // Passe la requête à la suite si permission OK
    : res.status(403).json({title: 'Permission refusée', status: 403}) // 403 si permissions !ok
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

// Middleware d'authentification vérifiant le jeton porteur (Bearer token)
function authenticate(req, res, next){
  // Extrait le token depuis l'entête Authorization HTTP
  const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') || '')

  if(!match)
    return res.status(401).json({title: 'Jeton Bearer requis', status: 401})

  try {
    const payload = jwt.verify(
      match[1], 
      secret('JWT_ACCESS_SECRET'), 
      { algorithms: ['HS256'] }
    );

    if(payload.tokenUse !== 'access' || !payload.sub || !PERMISSIONS[payload.role])
      throw new Error('claims invalides') // Valide l'usage du token (acccess) et l'existence du rôle et du sujet 

    req.user = payload;
    next()
  } catch {
    res.status(401).json({title: 'Jeton invalide', status: 401})
  }
}

const bankDetails = []
const documents = [
  { id: 1, ownerId: 'user-1', title: 'Dossier client', status: 'open' },
  { id: 2, ownerId: 'user-1', title: 'Dossier clôturé', status: 'closed' }
];

const Bank = z.object({
  iban: z.string().trim().regex(/^[A-Z]{2}[0-9A-Z]{13,32}$/)
}).strict()

const Login = z.strictObject({
  email: z.email().trim().toLowerCase(),
  password: z.string().min(6)
}).strict()

const Users = z.array(z.strictObject({
  id: z.string().min(1),
  email: z.email(),
  role: z.enum(['admin', 'auditor', 'user']),
  passwordHash: z.string().regex(/^\$2[aby]\$\d{2}\$.{53}$/)
})).min(1)

// Fonction extrayant et validant les utilisateurs configurés dans TP4_USERS_JSON (env)
function users(){
  const parsed = Users.safeParse(JSON.parse(process.env.TP4_USERS_JSON || '[]'))

  if(!parsed.success)
    throw new Error('TP4_USERS_JSON est invalide')

  return parsed.data // Retourne le tableau des utilisateurs validés
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const input = Login.safeParse(req.body) // Valider le format des données reçues via le schéma Zod Login
    if(!input.success)
      return res.status(422).json({title: 'Identifiants invalides', status: 422})

    // Recherche l'utilisateur correspondant dans la liste
    const user = users().find(entry => entry.email === input.data.email)

    if(!user || !(await bcrypt.compare(input.data.password, user.passwordHash)))
      return res.status(401).json({title: 'Identifiants invalides', status: 401})

    // On peut emettre le refresh token et le accesstoken
    refreshCookie(res, token(user, 'refresh'))
    // Renvoie l'access token signé valable 15 minutes (900 secondes)
    res.json({ accessToken: token(user, 'access'), expiresIn: 900 })
  } catch (error) {
    next(error)
  }
})

// Enpoint de renouvellement des jetons à partir du cookie de refresh
app.post('/api/v1/auth/refresh', (req, res) => {
  try {
    const payload = jwt.verify(
      req.cookies[REFRESH_COOKIE] || '',
      secret('JWT_REFRESH_SECRET'),
      { algorithms: ['HS256'] }
    );

    if(payload.tokenUse !== 'refresh' || !PERMISSIONS[payload.role] || typeof payload.sub !== 'string')
      throw new Error('Jeton invalide')

    const user = { id: payload.sub, role: payload.role };
    refreshCookie(req, token(user, 'refresh')) // Rotation du refresh token et renvoi un nouveau cookie
    res.json({
      accessToken: token(user, 'access'),
      expiresIn: 900
    })
  } catch {
    res.clearCookie(REFRESH_COOKIE, REFRESH_CLEAR_OPTIONS)
    res.status(401).json({title: 'Refresh token invalide ou expiré', status: 401})
  }
})

app.patch('/api/v1/documents', authenticate, requirePermission('document:update:any', 'document:update:own'), (req, res) => res.json(documents));

// Utilisation de RBAC
app.post('/api/v1/bank-details', authenticate, requirePermission('bank:create'), (req, res) => {
  const input = Bank.safeParse(req.body)

  if(!input.success)
    return res.status(422).json({title: 'IBAN invalide', status:422})

  const record = { id: bankDetails.length + 1, ownerId: String(req.user.sub), encrypted: encrypt(input.data.iban) }

  bankDetails.push(record)
  res.status(201).json({id: record.id, status:'encrypted'})
})

app.get('/api/v1/bank-details/:id', authenticate, requirePermission('bank:read:any', 'bank:read:own'), (req, res) => {
  const record = bankDetails.find(entry => entry.id === Number(req.params.id))

  if(!record)
    return res.status(404).json({title: 'Enregistrement introuvable', status: 404})

  // Applique la règle RBAC/ABAC : un utilisateur simple ne peut lire que ses propres données
  if(req.user.role === 'user' && record.ownerId !== String(req.user.sub))
      return res.status(403).json({title: 'Accès refusé', status: 403})

  res.json({ id: record.id, iban: decrypt(record.encrypted)})
})

// TODO 4 : chiffrer les coordonnées bancaires avec crypto_service.js.
// TODO 5 : empêcher une modification hors heures ouvrées ou d'un document closed.

const port = process.env.PORT || 3005;
if (require.main === module) {
  // Valide au démarrage la présence et la robustesse de tous les secrets nécessaires
  secret('JWT_ACCESS_SECRET');
  secret('JWT_REFRESH_SECRET');
  encryptionKey();
  users();
  
  app.listen(port, () => console.log(`TP4 démarré sur http://localhost:${port}`));
}

module.exports = app;
