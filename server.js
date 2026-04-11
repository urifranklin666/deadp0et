const http = require("http");

const config = require("./backend/config");
const { createRequestHandler } = require("./backend/app");
const { createBackendService } = require("./backend/service");
const { createStoreRepository } = require("./backend/store");

const repository = createStoreRepository(config);
const service = createBackendService(config, repository);
const server = http.createServer(createRequestHandler(config, service));

server.listen(config.PORT, config.HOST, () => {
  repository.ensureDirectory();
  console.log(`deadp0et backend listening on http://${config.HOST}:${config.PORT}`);
});
