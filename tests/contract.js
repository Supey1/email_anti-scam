// contract.js: checks that an input or a result follows docs/interfaces.md.
// Both workstreams use this: Person A on the engine's results, Person B on
// the scanner's inputs. Each function returns a list of problems ([] = fine).
//
// The reason codes are read straight from the table in docs/interfaces.md,
// so a new code only has to be added in one place.

const fs = require('fs');
const path = require('path');

const INTERFACES = fs.readFileSync(path.join(__dirname, '..', 'docs', 'interfaces.md'), 'utf8');
const codeTable = INTERFACES.split('### Reason codes')[1].split('\n---')[0];
const REASON_CODES = new Set([...codeTable.matchAll(/^\| `([A-Z_]+)` \|/gm)].map(m => m[1]));

const SOURCES = ['webpage', 'email', 'link'];
const CONTEXT_KEYS = {
  webpage: ['mainHeadings'],
  email: ['senderName', 'senderEmail', 'subject'],
  link: ['nearbyText', 'insideFrame', 'surroundingResult'],
};
const VERDICT_ACTIONS = {
  block: ['GO_BACK'],
  warn: ['GO_BACK', 'DO_NOT_ENTER_INFO', 'VERIFY_INDEPENDENTLY'],
  no_warning_signs: ['NONE'],
  unknown: ['NONE'],
};
const EVIDENCE_KINDS = ['url', 'domain', 'sender', 'text', 'form'];

const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);

// Only the listed keys, all of them present.
function checkKeys(obj, keys, where, problems, optional = []) {
  if (!isObject(obj)) { problems.push(`${where} must be an object`); return false; }
  for (const key of Object.keys(obj)) {
    if (!keys.includes(key) && !optional.includes(key)) problems.push(`${where} has a field the contract doesn't allow: "${key}"`);
  }
  for (const key of keys) if (!(key in obj)) problems.push(`${where} is missing "${key}"`);
  return true;
}

function validateInput(input) {
  const problems = [];
  if (!checkKeys(input, ['source', 'pageUrl', 'pageTitle', 'visibleText', 'links', 'forms', 'context'], 'input', problems)) return problems;

  if (!SOURCES.includes(input.source)) problems.push(`source must be one of ${SOURCES.join(', ')}`);
  for (const key of ['pageUrl', 'pageTitle', 'visibleText']) {
    if (typeof input[key] !== 'string') problems.push(`${key} must be a string`);
  }
  if (typeof input.visibleText === 'string' && input.visibleText.length > 50000) problems.push('visibleText must be at most 50,000 characters');

  if (!Array.isArray(input.links)) problems.push('links must be an array');
  else input.links.forEach((link, i) => {
    if (checkKeys(link, ['text', 'url'], `links[${i}]`, problems)) {
      if (typeof link.text !== 'string' || typeof link.url !== 'string') problems.push(`links[${i}] text and url must be strings`);
    }
  });
  if (input.source === 'link' && (!Array.isArray(input.links) || input.links.length !== 1)) {
    problems.push('a "link" input must have exactly one link: the one that was clicked');
  }

  // Privacy: forms may only say which sensitive fields exist, never what's in them.
  if (!Array.isArray(input.forms)) problems.push('forms must be an array');
  else input.forms.forEach((form, i) => {
    if (checkKeys(form, ['action', 'hasPassword', 'hasPaymentField'], `forms[${i}]`, problems)) {
      if (typeof form.action !== 'string') problems.push(`forms[${i}].action must be a string`);
      if (typeof form.hasPassword !== 'boolean' || typeof form.hasPaymentField !== 'boolean') {
        problems.push(`forms[${i}] hasPassword and hasPaymentField must be true or false`);
      }
    }
  });

  if (!isObject(input.context)) problems.push('context must be an object');
  else if (CONTEXT_KEYS[input.source]) {
    checkKeys(input.context, [], 'context', problems, CONTEXT_KEYS[input.source]);
    const ctx = input.context;
    if ('nearbyText' in ctx && (typeof ctx.nearbyText !== 'string' || ctx.nearbyText.length > 400)) {
      problems.push('context.nearbyText must be a string of at most 400 characters');
    }
    if ('mainHeadings' in ctx && (!Array.isArray(ctx.mainHeadings) || ctx.mainHeadings.length > 3)) {
      problems.push('context.mainHeadings must be a list of at most 3 headings');
    }
    if ('surroundingResult' in ctx && checkKeys(ctx.surroundingResult, ['verdict', 'recommendedAction'], 'context.surroundingResult', problems)) {
      const { verdict, recommendedAction } = ctx.surroundingResult;
      if (!(VERDICT_ACTIONS[verdict] || []).includes(recommendedAction)) problems.push('context.surroundingResult has an invalid verdict and action pair');
    }
  }
  return problems;
}

function validateResult(result) {
  const problems = [];
  if (!checkKeys(result, ['schemaVersion', 'verdict', 'reasons', 'recommendedAction', 'evidence'], 'result', problems)) return problems;

  if (result.schemaVersion !== 1) problems.push('schemaVersion must be 1');
  const actions = VERDICT_ACTIONS[result.verdict];
  if (!actions) problems.push(`verdict must be one of ${Object.keys(VERDICT_ACTIONS).join(', ')}`);
  else if (!actions.includes(result.recommendedAction)) {
    problems.push(`"${result.verdict}" can't have recommendedAction "${result.recommendedAction}" (allowed: ${actions.join(', ')})`);
  }

  if (!Array.isArray(result.reasons)) problems.push('reasons must be an array');
  else {
    const needsReasons = result.verdict === 'block' || result.verdict === 'warn';
    if (needsReasons && !result.reasons.length) problems.push(`"${result.verdict}" must give at least one reason`);
    if (!needsReasons && result.reasons.length) problems.push(`"${result.verdict}" must not give reasons`);
    result.reasons.forEach((reason, i) => {
      if (!checkKeys(reason, ['code', 'title', 'explanation'], `reasons[${i}]`, problems)) return;
      if (!REASON_CODES.has(reason.code)) problems.push(`reasons[${i}].code "${reason.code}" isn't in the reason-code table in docs/interfaces.md`);
      if (typeof reason.title !== 'string' || !reason.title.trim()) problems.push(`reasons[${i}].title must be a short label`);
      if (typeof reason.explanation !== 'string' || !reason.explanation.trim()) problems.push(`reasons[${i}].explanation must be a sentence`);
    });
  }

  if (!Array.isArray(result.evidence)) problems.push('evidence must be an array');
  else {
    const codes = new Set((Array.isArray(result.reasons) ? result.reasons : []).map(r => r && r.code));
    result.evidence.forEach((item, i) => {
      if (!checkKeys(item, ['kind', 'value', 'reasonCode'], `evidence[${i}]`, problems)) return;
      if (!EVIDENCE_KINDS.includes(item.kind)) problems.push(`evidence[${i}].kind must be one of ${EVIDENCE_KINDS.join(', ')}`);
      if (typeof item.value !== 'string') problems.push(`evidence[${i}].value must be a string`);
      if (!codes.has(item.reasonCode)) problems.push(`evidence[${i}].reasonCode "${item.reasonCode}" doesn't match any reason in this result`);
    });
  }
  return problems;
}

module.exports = { validateInput, validateResult, REASON_CODES };
