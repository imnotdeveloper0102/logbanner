const bcrypt = require('bcryptjs');
const db = require('./db');
const config = require('./config');

// Creates the first admin from ADMIN_EMAIL / ADMIN_PASSWORD when both are set.
// Safe to run repeatedly: an existing email is left untouched.
async function main() {
  if (!config.adminEmail || !config.adminPassword) {
    console.log('ADMIN_EMAIL or ADMIN_PASSWORD is not set, skipping admin seed');
    return;
  }
  const { rows } = await db.query('SELECT id FROM users WHERE lower(email) = lower($1)', [
    config.adminEmail,
  ]);
  if (rows.length > 0) {
    console.log(`Admin ${config.adminEmail} already exists, nothing to do`);
    return;
  }
  const passwordHash = await bcrypt.hash(config.adminPassword, 12);
  await db.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', [
    config.adminEmail,
    passwordHash,
    'admin',
  ]);
  console.log(`Created admin ${config.adminEmail}`);
}

main()
  .catch((err) => {
    console.error('Seed failed', err);
    process.exitCode = 1;
  })
  .finally(() => db.close());
