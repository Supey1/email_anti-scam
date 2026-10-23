// Measures accuracy on the labelled test set (tests/corpus/cases.js).
// Run with:  node tests/metrics.js            (prints the report; exits non-zero if a floor is broken)
//            node tests/metrics.js --write    (also writes docs/test-results.md)
//
// Metrics (definitions: docs/testing.md):
//   scam detection rate, false-positive rate, high-confidence block precision,
//   explanation accuracy, and click protection success (from the browser test, if it has been run).
// A high detection rate means nothing without the false-positive rate next to it.

const fs = require('fs');
const path = require('path');
const { analyze } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const { validateResult } = require(path.join(__dirname, 'contract.js'));
const Explain = require(path.join(__dirname, '..', 'extension', 'ui', 'explain.js'));
const cases = require('./corpus/cases.js');

// Regression floors. They are set a little below what was measured when they were written, so a real
// regression fails the test. They are NOT goals: the report lists every miss and false alarm.
const FLOORS = { detectionRate: 0.75, falsePositiveRateMax: 0.45, blockPrecision: 0.85, explanationAccuracy: 0.85, interruptedLegitimateMax: 1, /* the one known false positive, L-P11: fix it in the engine, then set this to 0 */ interruptRecall: 0.7 };

// Builds the contract input for a case (docs/interfaces.md) and asks the engine.
function run(c) {
  const i = c.input;
  const base = { pageTitle: '', visibleText: '', links: [], forms: [], context: {} };
  let input;
  if (c.kind === 'link') {
    input = { ...base, source: 'link', pageUrl: '', links: [{ text: i.text, url: i.href }], context: { nearbyText: '' } };
  } else if (c.kind === 'ad') {
    // What the click guard sends for a click inside an ad: the link, and the words around it.
    input = { ...base, source: 'link', pageUrl: i.pageUrl, links: [{ text: i.link[0], url: i.link[1] }], context: { nearbyText: i.text.slice(0, 400) } };
  } else if (c.kind === 'email') {
    input = { ...base, source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: i.subject, visibleText: i.text,
      links: i.links.map(([text, url]) => ({ text, url })), context: { senderName: i.senderName, senderEmail: i.senderEmail, subject: i.subject } };
  } else {
    input = { ...base, source: 'webpage', pageUrl: i.url, pageTitle: i.title, visibleText: i.text,
      links: (i.links || []).map(([text, url]) => ({ text, url })),
      forms: (i.forms || []).map(f => ({ action: f.action, hasPassword: !!f.hasPassword, hasPaymentField: !!(f.hasPaymentField || f.hasPayment) })), context: { mainHeadings: [] } };
  }
  const result = analyze(input);
  const problems = validateResult(result);
  if (problems.length) throw new Error(`${c.id}: the engine's result breaks the contract: ${problems.join('; ')}`);
  return result;
}

const flagged = r => r.verdict === 'warn' || r.verdict === 'block';
const interrupts = r => Explain.interrupts(r);
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : 'n/a');
const ratio = (n, d) => (d ? n / d : 1);

function measure() {
  const rows = cases.map(c => {
    const result = run(c);
    const model = Explain.describe(result);
    const shown = model.top.map(r => r.explanation).join(' ');
    const explainOk = flagged(result) && (c.explain || []).every(re => re.test(shown)) && !(c.forbid || []).some(re => re.test(shown));
    return { c, result, flagged: flagged(result), interrupted: interrupts(result), blocked: result.verdict === 'block', shown, explainOk };
  });
  const scams = rows.filter(r => r.c.label === 'scam');
  const legit = rows.filter(r => r.c.label === 'legit');
  const caught = scams.filter(r => r.flagged);
  const falseAlarms = legit.filter(r => r.flagged);
  const blocks = rows.filter(r => r.blocked);
  const goodBlocks = blocks.filter(r => r.c.label === 'scam' && r.c.blockCriteria === true);
  const stops = rows.filter(r => r.interrupted);
  const goodStops = stops.filter(r => r.c.label === 'scam'); // interrupting a scam is right; interrupting a legitimate case is the mistake
  const shouldStop = scams.filter(r => r.c.stopCriteria === true || r.c.blockCriteria === true);
  const explainable = caught.filter(r => r.c.explain);
  const accurate = explainable.filter(r => r.explainOk);
  const easy = scams.filter(r => !r.c.hard);
  const hard = scams.filter(r => r.c.hard);
  const byKind = {};
  for (const r of rows) {
    const k = (byKind[r.c.kind] = byKind[r.c.kind] || { scams: 0, caught: 0, legit: 0, falseAlarms: 0 });
    if (r.c.label === 'scam') { k.scams++; if (r.flagged) k.caught++; } else { k.legit++; if (r.flagged) k.falseAlarms++; }
  }
  return {
    rows, byKind,
    detection: { caught: caught.length, total: scams.length, easy: [easy.filter(r => r.flagged).length, easy.length], hard: [hard.filter(r => r.flagged).length, hard.length] },
    falsePositive: { flagged: falseAlarms.length, total: legit.length, hardBlocked: legit.filter(r => r.blocked).length, interrupted: legit.filter(r => r.interrupted).length },
    interruption: { caught: scams.filter(r => r.interrupted).length, total: scams.length, goodStops: goodStops.length, stops: stops.length, shouldStop: shouldStop.length, shouldStopDone: shouldStop.filter(r => r.interrupted).length },
    block: { goodBlocks: goodBlocks.length, blocks: blocks.length, missedBlockCriteria: scams.filter(r => r.c.blockCriteria && !r.blocked).length, blockCriteriaTotal: scams.filter(r => r.c.blockCriteria).length },
    explanation: { accurate: accurate.length, total: explainable.length },
    misses: scams.filter(r => !r.flagged), falseAlarms, badBlocks: blocks.filter(r => !(r.c.label === 'scam' && r.c.blockCriteria === true)),
    badStops: stops.filter(r => r.c.label !== 'scam'),
    missedStops: shouldStop.filter(r => !r.interrupted),
    badExplanations: explainable.filter(r => !r.explainOk),
  };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'results', file), 'utf8')); } catch (e) { return null; }
}

function report(m) {
  const lines = [];
  const L = (s = '') => lines.push(s);
  L('| Metric | Result | What it tells you |');
  L('|---|---|---|');
  L(`| Scam detection rate | ${pct(m.detection.caught, m.detection.total)} (${m.detection.caught}/${m.detection.total}) | Scam cases flagged (warn or block). Usual-looking scams ${m.detection.easy[0]}/${m.detection.easy[1]}; deliberately hard scams ${m.detection.hard[0]}/${m.detection.hard[1]} |`);
  L(`| False-positive rate | ${pct(m.falsePositive.flagged, m.falsePositive.total)} (${m.falsePositive.flagged}/${m.falsePositive.total}) | Legitimate cases flagged. Hard blocks among them: ${m.falsePositive.hardBlocked} |`);
  L(`| Interrupting warnings (they stop a click or cover a page) | Legitimate interrupted ${pct(m.falsePositive.interrupted, m.falsePositive.total)} (${m.falsePositive.interrupted}/${m.falsePositive.total}). Precision ${pct(m.interruption.goodStops, m.interruption.stops)} (${m.interruption.goodStops}/${m.interruption.stops}). Recall on cases that should interrupt ${pct(m.interruption.shouldStopDone, m.interruption.shouldStop)} (${m.interruption.shouldStopDone}/${m.interruption.shouldStop}) | Only GO_BACK and DO_NOT_ENTER_INFO interrupt. Weak warnings (VERIFY_INDEPENDENTLY) are shown but never stop anyone, so false alarms there cost far less |`);
  L(`| High-confidence block precision | ${pct(m.block.goodBlocks, m.block.blocks)} (${m.block.goodBlocks}/${m.block.blocks}) | Blocks that really meet the block criteria. Block criteria met but not blocked: ${m.block.missedBlockCriteria}/${m.block.blockCriteriaTotal} |`);
  L(`| Explanation accuracy | ${pct(m.explanation.accurate, m.explanation.total)} (${m.explanation.accurate}/${m.explanation.total}) | Flagged scams whose top three reasons mention the real evidence and make no wrong claim |`);
  const click = readJson('click-protection.json');
  L(`| Click protection success | ${click ? `${pct(click.stopped, click.supported)} (${click.stopped}/${click.supported})` : 'not measured (run the browser test)'} | Supported risky-click scenarios where navigation was really stopped |`);
  L('| Usability success | measured with people, not here | See `docs/usability-testing.md` |');
  L();
  L('| Kind | Scams caught | Legitimate flagged |');
  L('|---|---|---|');
  for (const [kind, k] of Object.entries(m.byKind)) L(`| ${kind} | ${k.caught}/${k.scams} | ${k.falseAlarms}/${k.legit} |`);
  const item = r => `- **${r.c.id}** ${r.c.summary}${r.c.hard ? ' _(written to be hard)_' : ''}${r.flagged ? ` → ${r.result.verdict}/${r.result.recommendedAction}: ${r.shown.slice(0, 160)}` : ''}`;
  L();
  L(`### Scams that were NOT flagged (${m.misses.length})`);
  L(m.misses.length ? m.misses.map(item).join('\n') : 'None.');
  L();
  L(`### Legitimate cases that WERE flagged (${m.falseAlarms.length})`);
  L(m.falseAlarms.length ? m.falseAlarms.map(item).join('\n') : 'None.');
  L();
  L(`### Hard blocks that do not meet the block criteria (${m.badBlocks.length})`);
  L(m.badBlocks.length ? m.badBlocks.map(item).join('\n') : 'None.');
  L();
  L(`### Legitimate cases that were INTERRUPTED (the costly mistake) (${m.badStops.length})`);
  L(m.badStops.length ? m.badStops.map(item).join('\n') : 'None.');
  L();
  L(`### Cases that should interrupt but did not (${m.missedStops.length})`);
  L(m.missedStops.length ? m.missedStops.map(item).join('\n') : 'None.');
  L();
  L(`### Flagged scams whose explanation was inaccurate or incomplete (${m.badExplanations.length})`);
  L(m.badExplanations.length ? m.badExplanations.map(r => `${item(r)}`).join('\n') : 'None.');
  const perf = readJson('performance.json');
  if (perf) {
    L();
    L('### Performance');
    L('| Measure | Result |');
    L('|---|---|');
    for (const [k, v] of Object.entries(perf.measures)) L(`| ${k} | ${v} |`);
  }
  return lines.join('\n');
}

function checkFloors(m) {
  const failures = [];
  if (ratio(m.detection.caught, m.detection.total) < FLOORS.detectionRate) failures.push('scam detection rate fell below its floor');
  if (ratio(m.falsePositive.flagged, m.falsePositive.total) > FLOORS.falsePositiveRateMax) failures.push('false-positive rate rose above its ceiling');
  if (ratio(m.block.goodBlocks, m.block.blocks) < FLOORS.blockPrecision) failures.push('block precision fell below its floor');
  if (ratio(m.explanation.accurate, m.explanation.total) < FLOORS.explanationAccuracy) failures.push('explanation accuracy fell below its floor');
  if (m.falsePositive.hardBlocked > 0) failures.push('a legitimate case was hard-blocked');
  if (m.falsePositive.interrupted > FLOORS.interruptedLegitimateMax) failures.push('a legitimate case was interrupted');
  if (ratio(m.interruption.shouldStopDone, m.interruption.shouldStop) < FLOORS.interruptRecall) failures.push('interruption recall fell below its floor');
  return failures;
}

if (require.main === module) {
  const m = measure();
  const text = report(m);
  console.log(text);
  if (process.argv.includes('--write')) {
    const header = '# Test results\n\nGenerated by `node tests/metrics.js --write` from `tests/corpus/cases.js`. This is a development set: it shows what works and what does not, not how the extension will do in the world. Definitions and method: [`testing.md`](testing.md).\n\n';
    fs.writeFileSync(path.join(__dirname, '..', 'docs', 'test-results.md'), header + text + '\n');
    console.log('\nWrote docs/test-results.md');
  }
  const failures = checkFloors(m);
  console.log(failures.length ? `\nFAILED: ${failures.join('; ')}` : '\nAll metric floors held.');
  process.exitCode = failures.length ? 1 : 0;
}

module.exports = { measure, run, report, checkFloors, FLOORS };
