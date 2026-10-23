// Tests the usability scoring script with made-up rows (these are NOT study results).
// Run with:  node tests/usability-score.js is the real tool; this checks the arithmetic.
const assert = require('assert');
const { parseCsv, score } = require('./usability-score.js');

const csv = `participant_id,scenario_id,understood_verdict,reason_accuracy,next_step_appropriate,needed_help,seconds_to_decision,hesitation_notes,misunderstanding_notes
P1,U01,1,2,1,0,10,,
P1,U02,1,1,1,1,40,"asked what 'caution' meant",
P2,U01,0,0,0,0,25,,"thought the red box was an ad"
P2,U02,1,2,0,0,15,"read it twice, then ""clicked the link anyway""",
`;
const rows = parseCsv(csv);
assert.strictEqual(rows.length, 4);
assert.strictEqual(rows[3].hesitation_notes, 'read it twice, then "clicked the link anyway"', 'quotes inside notes survive');

const s = score(rows);
assert.strictEqual(s.attempts, 4);
assert.strictEqual(s.participants, 2);
assert.strictEqual(s.success, 0.25, 'only P1/U01 understood, chose well, and needed no help');
assert.strictEqual(s.understood, 0.75);
assert.strictEqual(s.neededHelp, 0.25);
assert.strictEqual(s.reasonAccuracy, (2 + 1 + 0 + 2) / 8);
assert.strictEqual(s.perScenario[0].success, 0, 'hardest scenario is listed first');
assert.strictEqual(s.notes.length, 3);
assert.strictEqual(score([]).success, null, 'no data gives n/a, not 0%');

console.log('PASS  usability scoring arithmetic\n\nAll tests passed');
