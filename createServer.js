const fs = require('fs');
const http = require('http');
const https = require('https');

const postgres = require('postgres-fp/promises');

const { getCertificate, handleHttpChallenge } = require('./acmeUtilities');
const config = require('./config');

const defaultCertificates = {
  key: fs.readFileSync('./certs/default.key', 'ascii'),
  cert: fs.readFileSync('./certs/default.cert', 'ascii')
};

async function createServer () {
  const db = await postgres.connect(config.cockroach);

  const options = {
    SNICallback: getCertificate(db, { defaultCertificates })
  };

  async function handler (request, response) {
    const record = await postgres.getOne(db, `
      SELECT dockerhost, dockerid, dockerport
        FROM deployments
    LEFT JOIN projects ON projects.id = deployments.projectId
        WHERE domain = $1
    ORDER BY random()
        LIMIT 1
    `, [request.headers.host]);

    if (!record) {
      response.writeHead(404);
      response.end(`Domain ${request.headers.host} is not hosted here`);
      return;
    }

    const proxyRequest = http.request(`http://${record.dockerhost}:${record.dockerport}${request.url}`, function (proxyResponse) {
      proxyResponse.pipe(response);
    });

    proxyRequest.end();
  }

  const httpsServer = https.createServer(options, handler);
  httpsServer.on('listening', () => {
    console.log('Listening https on port:', httpsServer.address().port);
  });
  httpsServer.listen(443);

  const httpServer = http.createServer(async function (request, response) {
    if (handleHttpChallenge(db, request, response)) {
      return;
    }

    response.writeHead(404);
    response.end('Letsnot - 404 - Not Found');
  });
  httpServer.on('listening', () => {
    console.log('Listening https on port:', httpServer.address().port);
  });
  httpServer.listen(80);
}

module.exports = createServer;
