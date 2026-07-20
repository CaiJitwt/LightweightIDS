const DB_NAME = "ids-personalization";
const STORE_NAME = "images";
const DB_VERSION = 1;

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withStore(
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest | void,
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, mode);
    const store = transaction.objectStore(STORE_NAME);
    const request = op(store);
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); reject(transaction.error); };
    if (request) request.onerror = () => { db.close(); reject(request.error); };
  });
}

async function getImage(key: string): Promise<string | undefined> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(key);
    transaction.oncomplete = () => db.close();
    request.onsuccess = () => resolve(request.result as string | undefined);
    request.onerror = () => { db.close(); reject(request.error); };
  });
}

async function setImage(key: string, dataUrl: string): Promise<void> {
  await withStore("readwrite", (store) => store.put(dataUrl, key));
}

async function removeImage(key: string): Promise<void> {
  await withStore("readwrite", (store) => store.delete(key));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface PersonalizationState {
  accent: string;
  componentTint: string;
  componentOpacity: number;
  componentBlur: number;
  tableTint: string;
  tableOpacity: number;
  tableBlur: number;
  background: string;
  backgroundPosition: "center" | "top-left" | "top-right" | "bottom-left" | "bottom-right";
  backgroundSize: "cover" | "contain" | "stretch" | "original";
  backgroundOpacity: number;
  petImage: string;
  petPosition: "bottom-right" | "bottom-left" | "top-right" | "top-left";
  petSize: number;
  petOpacity: number;
}

export const defaultPersonalization: PersonalizationState = {
  accent: "#2677bd",
  componentTint: "#7ea7c4",
  componentOpacity: 92,
  componentBlur: 6,
  tableTint: "#8ca6b8",
  tableOpacity: 94,
  tableBlur: 4,
  background: "",
  backgroundPosition: "center",
  backgroundSize: "cover",
  backgroundOpacity: 100,
  petImage: "",
  petPosition: "bottom-right",
  petSize: 96,
  petOpacity: 85,
};

const CONFIG_KEY = "ids-prototype-personalization";
const INDEXEDDB_PREFIX = "indexeddb:";

/** Replace stored image keys with actual data URLs loaded from IndexedDB. */
export async function loadPersonalization(): Promise<[PersonalizationState, boolean]> {
  const raw = localStorage.getItem(CONFIG_KEY);
  if (!raw) return [defaultPersonalization, false];

  let config: Record<string, unknown>;
  try { config = JSON.parse(raw); }
  catch { return [defaultPersonalization, true]; }

  const state = { ...defaultPersonalization, ...config } as PersonalizationState;

  // Load images from IndexedDB (or migrate old base64 data URLs on first access).
  if (state.background && typeof state.background === "string") {
    if (state.background.startsWith(INDEXEDDB_PREFIX)) {
      const key = state.background.slice(INDEXEDDB_PREFIX.length);
      state.background = (await getImage(key)) ?? "";
      if (!state.background) config.background = "";
    } else if (state.background.startsWith("data:")) {
      // Migrate old base64 data to IndexedDB.
      const migrated = state.background;
      try { await setImage("background", migrated); } catch { /* keep in localStorage */ }
      config.background = INDEXEDDB_PREFIX + "background";
      localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
    }
  }

  if (state.petImage && typeof state.petImage === "string") {
    if (state.petImage.startsWith(INDEXEDDB_PREFIX)) {
      const key = state.petImage.slice(INDEXEDDB_PREFIX.length);
      state.petImage = (await getImage(key)) ?? "";
      if (!state.petImage) config.petImage = "";
    } else if (state.petImage.startsWith("data:")) {
      const migrated = state.petImage;
      try { await setImage("petImage", migrated); } catch { /* keep in localStorage */ }
      config.petImage = INDEXEDDB_PREFIX + "petImage";
      localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
    }
  }

  return [state, false];
}

/** Persist config to localStorage and images to IndexedDB. */
export async function savePersonalization(state: PersonalizationState): Promise<void> {
  const config: Record<string, unknown> = { ...state };

  if (state.background && state.background.startsWith("data:")) {
    try { await setImage("background", state.background); } catch { throw new Error("Browser storage is full."); }
    config.background = INDEXEDDB_PREFIX + "background";
  } else if (!state.background) {
    config.background = "";
    try { await removeImage("background"); } catch { /* best effort */ }
  }

  if (state.petImage && state.petImage.startsWith("data:")) {
    try { await setImage("petImage", state.petImage); } catch { throw new Error("Browser storage is full."); }
    config.petImage = INDEXEDDB_PREFIX + "petImage";
  } else if (!state.petImage) {
    config.petImage = "";
    try { await removeImage("petImage"); } catch { /* best effort */ }
  }

  localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
}
