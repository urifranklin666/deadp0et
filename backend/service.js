const { createAuthService } = require("./auth");
const { createDeviceService } = require("./devices");
const { createMessageService } = require("./messages");
const { createPrekeyService } = require("./prekeys");
const { createPushService } = require("./push");
const { createSharedContext } = require("./shared");

function createBackendService(config, repository) {
  const ctx = createSharedContext(config, repository);
  const auth = createAuthService(ctx);
  const prekeys = createPrekeyService(ctx);
  const push = createPushService(ctx, auth);
  const messages = createMessageService(ctx, auth, prekeys, push);
  const devices = createDeviceService(ctx, auth, prekeys, push);

  return {
    handleAcknowledgeInbox: messages.handleAcknowledgeInbox,
    handleConversations: messages.handleConversations,
    handleCreateAccount: auth.handleCreateAccount,
    handleCreateSession: auth.handleCreateSession,
    handleDeleteCurrentSession: auth.handleDeleteCurrentSession,
    handleDeleteSession: auth.handleDeleteSession,
    handleDeleteDevice: devices.handleDeleteDevice,
    handleGetBundles: prekeys.handleGetBundles,
    handleHealth: devices.handleHealth,
    handleHistory: messages.handleHistory,
    handleInbox: messages.handleInbox,
    handleRetentionRun: messages.handleRetentionRun,
    handleIssuePrekeyBundle: prekeys.handleIssuePrekeyBundle,
    handleListPushRegistrations: push.handleListRegistrations,
    handleListSessions: auth.handleListSessions,
    handleListDevices: devices.handleListDevices,
    handleRegisterPushToken: push.handleRegisterPushToken,
    handleRegisterDevice: devices.handleRegisterDevice,
    handleRotatePrekeys: devices.handleRotatePrekeys,
    handleStoreMessage: messages.handleStoreMessage,
    handleDeletePushToken: push.handleDeletePushToken,
    requireAuth: auth.requireAuth
  };
}

module.exports = {
  createBackendService
};
