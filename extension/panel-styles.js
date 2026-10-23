// panel-styles.js: the look of the safety panel.
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

// Styles for the warning card (ui/warning-view.js): the extension's warning page and the in-page panel.
// Severity is shown by an icon, a word, AND a colour, never by colour alone.
const WARNING_CSS = `
.backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.65);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  box-sizing: border-box;
}
.card {
  width: 560px;
  max-width: 100%;
  max-height: 100%;
  overflow-y: auto;
  box-sizing: border-box;
  background: #ffffff;
  color: #111111;
  border: 4px solid #222222;
  border-radius: 14px;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
  font-family: Arial, Helvetica, sans-serif;
  font-size: 24px; /* the person's text size setting replaces this */
  line-height: 1.5;
}
.card.high { border-color: #b00020; border-style: solid; }
.card.medium { border-color: #8a6d00; border-style: dashed; }
.card.low { border-color: #1b7f3b; }
.card.corner { position: fixed; top: 72px; right: 16px; width: 420px; max-height: calc(100vh - 96px); }
.card .verdict { margin: 14px; align-items: center; font-size: 1em; }
.card .verdict .icon { font-size: 2em; }
.card .verdict .label { font-size: 0.8em; letter-spacing: 0.08em; }
.card .verdict h1 { margin: 0; font-size: 1.4em; line-height: 1.2; }
.card h2 { font-size: 1.05em; margin: 12px 0 6px; }
.card .section { padding: 4px 18px 8px; }
.card ul { margin: 4px 0; padding-left: 26px; }
.card li { margin: 8px 0; }
.card details.more { margin: 8px 0; }
.card summary { cursor: pointer; font-weight: bold; padding: 6px 0; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; padding: 6px 18px 18px; }
.card button { font-size: 0.9em; }
.actions .primary { background: #0b3d91; color: #ffffff; border-color: #062a66; font-size: 1.2em; padding: 12px 18px; }
.actions .primary:hover { background: #062a66; }
.actions .quiet { font-size: 0.85em; font-weight: normal; background: #f4f4f4; }
.dest { word-break: break-all; font-weight: bold; }
.card .extra p { margin: 3px 0; }
.card .extra .muted { font-size: 0.9em; }
.card .extra .flag { color: #b00020; font-weight: bold; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
button:focus-visible, summary:focus-visible { outline: 4px solid #1a56db; outline-offset: 2px; }
@media (prefers-contrast: more) {
  .card { border-width: 6px; }
  .quiet { background: #ffffff; border-width: 3px; }
}
@media (forced-colors: active) {
  .card, button { border: 3px solid CanvasText; }
  button:focus-visible, summary:focus-visible { outline: 4px solid Highlight; }
}
@media (max-width: 480px) { .card.corner { left: 8px; right: 8px; width: auto; } }
`;
