const { createAuthService } = require("./auth");
const { createDeviceService } = require("./devices");
const { createMessageService } = require("./messages");
const { createPrekeyService } = require("./prekeys");
const { createSharedContext } = require("./shared");

function createBackendService(config, repository) {
  const ctx = createSharedContext(config, repository);
  const auth = createAuthService(ctx);
  const prekeys = createPrekeyService(ctx);
  const messages = createMessageService(ctx, auth, prekeys);
  const devices = createDeviceService(ctx, auth, prekeys);

  return {
    handleAcknowledgeInbox: messages.handleAcknowledgeInbox,
    handleCreateAccount: auth.handleCreateAccount,
    handleCreateSession: auth.handleCreateSession,
    handleDeleteDevice: devices.handleDeleteDevice,
    handleGetBundles: prekeys.handleGetBundles,
    handleHealth: devices.handleHealth,
    handleInbox: messages.handleInbox,
    handleIssuePrekeyBundle: prekeys.handleIssuePrekeyBundle,
    handleListDevices: devices.handleListDevices,
    handleRegisterDevice: devices.handleRegisterDevice,
    handleRotatePrekeys: devices.handleRotatePrekeys,
    handleStoreMessage: messages.handleStoreMessage,
    requireAuth: auth.requireAuth
  };
}

module.exports = {
  createBackendService
};
