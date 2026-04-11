const fs = require("fs");

function ensureDirectory(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function defaultStore() {
  return {
    accounts: [],
    sessions: [],
    messages: [],
    prekeyReservations: []
  };
}

function loadStore(dataFile) {
  try {
    const raw = fs.readFileSync(dataFile, "utf8");
    const parsed = JSON.parse(raw);
    return {
      accounts: Array.isArray(parsed.accounts) ? parsed.accounts : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      messages: Array.isArray(parsed.messages) ? parsed.messages : [],
      prekeyReservations: Array.isArray(parsed.prekeyReservations) ? parsed.prekeyReservations : []
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      return defaultStore();
    }
    throw error;
  }
}

function createStoreRepository(config) {
  const store = loadStore(config.DATA_FILE);

  function saveStore() {
    ensureDirectory(config.DATA_DIR);
    fs.writeFileSync(config.DATA_FILE, JSON.stringify(store, null, 2));
  }

  function createCollectionRepository(key) {
    return {
      all() {
        return store[key];
      },
      count(predicate = null) {
        return predicate ? store[key].filter(predicate).length : store[key].length;
      },
      filter(predicate) {
        return store[key].filter(predicate);
      },
      find(predicate) {
        return store[key].find(predicate) || null;
      },
      forEach(callback) {
        store[key].forEach(callback);
      },
      push(item) {
        store[key].push(item);
        return item;
      }
    };
  }

  return {
    accounts: createCollectionRepository("accounts"),
    messages: createCollectionRepository("messages"),
    prekeyReservations: createCollectionRepository("prekeyReservations"),
    sessions: createCollectionRepository("sessions"),
    ensureDirectory() {
      ensureDirectory(config.DATA_DIR);
    },
    saveStore,
    snapshot() {
      return store;
    }
  };
}

module.exports = {
  createStoreRepository,
  defaultStore,
  ensureDirectory
};
