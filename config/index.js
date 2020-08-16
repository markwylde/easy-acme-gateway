const fs = require('fs');

module.exports = {
  email: 'me@markwylde.com',
  cockroach: {
    host: '192.168.1.1',
    database: 'postgres',
    user: 'root',
    port: 26257,
    ssl: {
      rejectUnauthorized: false,
      ca: fs.readFileSync('./certs/database/ca.crt').toString(),
      key: fs.readFileSync('./certs/database/client.key').toString(),
      cert: fs.readFileSync('./certs/database/client.crt').toString()
    }
  }
};
