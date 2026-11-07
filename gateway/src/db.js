const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({ connectionString: config.databaseUrl, max: 10 });

pool.on('error', (err) => {
  console.error('Idle Postgres client error', err);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  close: () => pool.end(),
};
