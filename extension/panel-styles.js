// panel-styles.js: the look of the Gmail safety panel and the full-screen warning.
// It's plain CSS inside a JavaScript string so it can be put inside the panel's
// "shadow DOM", which keeps Gmail's styles and ours from messing each other up.
// Design rules: big text, high contrast, color AND icons (never color alone).

const PANEL_CSS = `
:host {
  all: initial;
  position: fixed;
  top: 72px;
  right: 16px;
  z-index: 2147483647;
  font-family: Arial, Helvetica, sans-serif;
}

.panel {
  width: 400px;
  max-height: calc(100vh - 96px);
  overflow-y: auto;
  background: #ffffff;
  color: #111111;
  border: 3px solid #222222;
  border-radius: 14px;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
  font-size: 20px;
  line-height: 1.45;
}

.header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 14px;
  border-bottom: 2px solid #dddddd;
  background: #f4f4f4;
  border-radius: 12px 12px 0 0;
}
.header .title { flex: 1; font-weight: bold; font-size: 20px; }

button {
  font: inherit;
  font-size: 18px;
  font-weight: bold;
  padding: 8px 12px;
  border: 2px solid #222222;
  border-radius: 10px;
  background: #ffffff;
  color: #111111;
  cursor: pointer;
}
button:hover, button:focus-visible { background: #e8eefc; outline: 3px solid #1a56db; }

.verdict {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 14px;
  padding: 16px;
  border-radius: 12px;
  font-size: 26px;
  font-weight: bold;
  line-height: 1.2;
}
.verdict .icon { font-size: 40px; }
.verdict.high   { background: #b00020; color: #ffffff; }
.verdict.medium { background: #ffd54a; color: #111111; border: 3px solid #8a6d00; }
.verdict.low    { background: #1b7f3b; color: #ffffff; }

.section { padding: 4px 18px 14px; }
.section h3 { font-size: 21px; margin: 10px 0 6px; }
.section p { margin: 4px 0; }
.section ul { margin: 4px 0; padding-left: 26px; }
.section li { margin: 8px 0; }
.muted { color: #444444; font-size: 18px; word-break: break-all; }
.preview { font-size: 18px; color: #333333; }
.flag { color: #b00020; font-weight: bold; }

.reopen {
  font-size: 20px;
  padding: 12px 16px;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.3);
}
.reopen.high   { background: #b00020; color: #ffffff; }
.reopen.medium { background: #ffd54a; }
.reopen.low    { background: #1b7f3b; color: #ffffff; }

[hidden] { display: none !important; }
`;

// The full-screen "Stop and check" warning (warning.js).
// Same design rules, but bigger: it has to win over everything else on the page.
const WARNING_CSS = `
:host {
  all: initial;
  position: fixed;
  inset: 0;
  z-index: 2147483647;
  font-family: Arial, Helvetica, sans-serif;
}

.backdrop {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  background: rgba(0, 0, 0, 0.7);
}

.dialog {
  width: 640px;
  max-width: 100%;
  max-height: calc(100vh - 32px);
  overflow-y: auto;
  background: #ffffff;
  color: #111111;
  border: 4px solid #b00020;
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
  font-size: 22px;
  line-height: 1.45;
}
.dialog.page { border-color: #8a6d00; }

.verdict {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 20px;
  border-radius: 12px 12px 0 0;
  background: #b00020;
  color: #ffffff;
  font-size: 30px;
  font-weight: bold;
  line-height: 1.2;
}
.verdict .icon { font-size: 44px; }
.dialog.page .verdict { background: #ffd54a; color: #111111; }

.where { margin: 16px 22px 0; overflow-wrap: anywhere; }

.section { padding: 4px 22px 12px; }
.section h3 { font-size: 23px; margin: 12px 0 6px; }
.section ul { margin: 4px 0; padding-left: 28px; }
.section li { margin: 8px 0; }

.buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  padding: 8px 22px 12px;
}

button {
  font: inherit;
  font-weight: bold;
  border: 3px solid #222222;
  border-radius: 12px;
  background: #ffffff;
  color: #111111;
  cursor: pointer;
}
button:hover, button:focus-visible { outline: 4px solid #1a56db; outline-offset: 2px; }

.back {
  flex: 1;
  min-width: 260px;
  padding: 16px 20px;
  font-size: 26px;
  background: #1b7f3b;
  border-color: #0f4d23;
  color: #ffffff;
}
.read { padding: 16px 20px; font-size: 22px; }

/* Deliberately small and plain: it must be possible, but never the easy choice. */
.continue {
  display: block;
  margin: 4px 22px 20px;
  padding: 6px 10px;
  border: none;
  background: none;
  color: #444444;
  font-size: 17px;
  font-weight: normal;
  text-decoration: underline;
}
`;
