# Renderer design preview

From `ui/`, run `npm exec vite -- --host 127.0.0.1 --port 5173` and open
`http://127.0.0.1:5173/preview.html`.

This renders the same React UI with an in-memory Electron bridge. Traffic, logs,
start/stop, saving, and folder scanning are simulated. Reloading the page resets
the fixture. It never reads local credentials or configuration and never loads a
driver. The preview entry and bridge are excluded from the default production
build; the Electron app continues to use its real preload bridge.
