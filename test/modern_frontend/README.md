# Lightweight IDS Modern Frontend Prototype

This isolated React prototype explores a denser, more modern analyst workflow without replacing or modifying the PySide6 application. All data is local mock data and no backend detection or database logic is executed.

## Run

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:4173`.

## Verify

```powershell
npm test
npm run build
# Keep `npm run dev` running in another terminal before this command.
npm run test:e2e
```

The prototype covers Dashboard, Traffic Monitor, Host Explorer and Alert Center. Its TypeScript records mirror the current Python packet, alert and host profile shapes so a future read-only Qt WebChannel or local API adapter can replace the mock source.
