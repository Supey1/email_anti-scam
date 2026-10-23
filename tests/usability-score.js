// Scores usability sessions from a results sheet.  node tests/usability-score.js path/to/results.csv
// Columns (see tests/usability/results-template.csv and docs/usability-testing.md):
//   participant_id, scenario_id, understood_verdict, reason_accuracy, next_step_appropriate, needed_help, seconds_to_decision, hesitation_notes, misunderstanding_notes
//   understood_verdict, next_step_appropriate, needed_help: 1 or 0.   reason_accuracy: 0 wrong, 1 partly right, 2 right.
// Usability success = share of scenario attempts where the person understood the verdict AND chose an appropriate next step WITHOUT help.

const fs = require('fs');

function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (ch === '"') quoted = false; else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(cell); cell = ''; if (row.some(c => c !== '')) rows.push(row); row = []; }
    else cell += ch;
  }
  if (cell !== '' || row.length) { row.push(cell); if (row.some(c => c !== '')) rows.push(row); }
  const [header, ...body] = rows;
  return body.map(r => Object.fromEntries(header.map((h, i) => [h.trim(), (r[i] || '').trim()])));
}

function score(records) {
  const flag = v => v === '1' || v === 1;
  const rows = records.filter(r => r.scenario_id);
  const ok = r => flag(r.understood_verdict) && flag(r.next_step_appropriate) && !flag(r.needed_help);
  const by = (key, list) => { const m = {}; for (const r of list) (m[r[key]] = m[r[key]] || []).push(r); return m; };
  const per = Object.entries(by('scenario_id', rows)).map(([id, list]) => ({
    id, n: list.length,
    success: list.filter(ok).length / list.length,
    understood: list.filter(r => flag(r.understood_verdict)).length / list.length,
    helped: list.filter(r => flag(r.needed_help)).length / list.length,
    reason: list.reduce((a, r) => a + Number(r.reason_accuracy || 0), 0) / (2 * list.length),
  }));
  return {
    attempts: rows.length,
    participants: new Set(rows.map(r => r.participant_id)).size,
    success: rows.length ? rows.filter(ok).length / rows.length : null,
    understood: rows.length ? rows.filter(r => flag(r.understood_verdict)).length / rows.length : null,
    reasonAccuracy: rows.length ? rows.reduce((a, r) => a + Number(r.reason_accuracy || 0), 0) / (2 * rows.length) : null,
    neededHelp: rows.length ? rows.filter(r => flag(r.needed_help)).length / rows.length : null,
    perScenario: per.sort((a, b) => a.success - b.success), // the hardest scenarios first
    notes: rows.filter(r => r.hesitation_notes || r.misunderstanding_notes).map(r => ({ participant: r.participant_id, scenario: r.scenario_id, hesitation: r.hesitation_notes, misunderstanding: r.misunderstanding_notes })),
  };
}

const pct = v => (v === null ? 'n/a' : `${(100 * v).toFixed(0)}%`);

if (require.main === module) {
  const file = process.argv[2];
  if (!file) { console.log('Usage: node tests/usability-score.js results.csv'); process.exit(1); }
  const s = score(parseCsv(fs.readFileSync(file, 'utf8')));
  console.log(`${s.attempts} attempts from ${s.participants} participant(s)`);
  console.log(`Usability success (understood AND chose an appropriate next step, without help): ${pct(s.success)}`);
  console.log(`Understood the verdict: ${pct(s.understood)}   Explained the reason correctly: ${pct(s.reasonAccuracy)}   Needed help: ${pct(s.neededHelp)}`);
  console.log('\nScenario (hardest first): success / understood / needed help');
  for (const p of s.perScenario) console.log(`  ${p.id}: ${pct(p.success)} / ${pct(p.understood)} / ${pct(p.helped)}  (n=${p.n})`);
  console.log(`\nNotes (${s.notes.length}):`);
  for (const n of s.notes) console.log(`  ${n.participant} ${n.scenario}: ${[n.hesitation && `hesitated: ${n.hesitation}`, n.misunderstanding && `misunderstood: ${n.misunderstanding}`].filter(Boolean).join(' | ')}`);
}

module.exports = { parseCsv, score };
