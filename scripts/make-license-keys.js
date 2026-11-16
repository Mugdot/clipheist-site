// One-off setup: creates the licence signing keypair and a download secret.
// Private key -> website/.env, public key -> app/src/config.json. Re-running keeps existing values.
const crypto = require('crypto'), fs = require('fs'), path = require('path');

const envPath = path.join(__dirname, '..', '.env');
const cfgPath = path.join(__dirname, '..', '..', 'app', 'src', 'config.json');
let env = fs.readFileSync(fs.existsSync(envPath) ? envPath : path.join(__dirname, '..', '.env.example'), 'utf8');
const line = (k) => new RegExp(`^${k}=.*$`, 'm');
const get = (k) => ((env.match(line(k)) || [''])[0].split('=').slice(1).join('=')).trim();
const set = (k, v) => { env = line(k).test(env) ? env.replace(line(k), () => `${k}=${v}`) : `${env}\n${k}=${v}\n`; };

if (!get('DOWNLOAD_SECRET')) set('DOWNLOAD_SECRET', crypto.randomBytes(32).toString('hex'));
const cfg = fs.existsSync(cfgPath) ? JSON.parse(fs.readFileSync(cfgPath, 'utf8')) : {};
cfg.licenseServer = cfg.licenseServer || 'http://localhost:3000';
if (!get('LICENSE_PRIVATE_KEY') || !cfg.publicKey) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  set('LICENSE_PRIVATE_KEY', privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'));
  cfg.publicKey = publicKey.export({ type: 'spki', format: 'pem' });
  console.log('New signing key created.');
} else console.log('Existing signing key kept.');
fs.writeFileSync(envPath, env);
fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
console.log('Wrote website/.env and app/src/config.json');
