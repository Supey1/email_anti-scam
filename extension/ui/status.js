// status.js: the popup's plain answer to "is this page being checked?"
// Pure function: settings and what the page reported go in, words come out.
// `reply` is what the page's checker said when asked (undefined if it didn't answer).
// `access` is the website access Chrome has given ('all' | 'gmail' | 'none', from the service worker).

const SETTINGS = (typeof module !== 'undefined') ? require('../settings.js') : Settings;
const PopupStatus = (() => {
  const WEB = /^https?:$/;

  const NO_ACCESS = 'Open Settings and choose which websites to check. Chrome will ask you to allow it.';

  function describePage({ settings, url, reply, access = 'all' }) {
    let parsed = null;
    try { parsed = url ? new URL(url) : null; } catch (e) { parsed = null; }

    if (!settings.enabled) {
      return { state: 'no', icon: '⛔', text: 'No, this page is not being checked.', detail: 'Protection is turned off.', toggle: null };
    }
    if (!parsed || !WEB.test(parsed.protocol)) {
      return { state: 'no', icon: '⛔', text: 'This page cannot be checked.', detail: 'Chrome does not let extensions look at this kind of page.', toggle: null };
    }
    const host = parsed.hostname;

    if (host === 'mail.google.com') {
      if (access === 'none') {
        return { state: 'no', icon: '⛔', text: 'No, Gmail is not being checked yet.', detail: NO_ACCESS, toggle: null };
      }
      if (!settings.checkEmail) {
        return { state: 'no', icon: '⛔', text: 'No, Gmail emails are not being checked.', detail: 'You turned this off in Settings.', toggle: null };
      }
      return reply && reply.checking
        ? { state: 'yes', icon: '✅', text: 'Yes. Emails you open in Gmail are being checked.', detail: 'This happens on this computer. Nothing is sent anywhere.', toggle: null }
        : notSure();
    }

    if (access !== 'all') {
      return { state: 'no', icon: '⛔', text: 'No, this website is not being checked.', detail: NO_ACCESS, toggle: null };
    }
    if (!SETTINGS.shouldCheckSite(settings, host)) {
      const chosen = settings.siteMode === 'chosen';
      return {
        state: 'no', icon: '⛔',
        text: 'No, this website is not being checked.',
        detail: chosen ? 'You chose to check only some websites, and this is not one of them.' : 'You turned protection off for this website.',
        toggle: { label: chosen ? 'Check this website' : 'Turn on for this website', on: true },
      };
    }
    return reply && reply.checking
      ? { state: 'yes', icon: '✅', text: 'Yes, this page is being checked.', detail: 'We look at its words, links, and forms on this computer. Nothing is sent anywhere.', toggle: { label: 'Turn off for this website', on: false } }
      : { ...notSure(), toggle: { label: 'Turn off for this website', on: false } };
  }

  function notSure() {
    return { state: 'unknown', icon: '❔', text: 'Not sure yet.', detail: 'Reload this page to start checking it.', toggle: null };
  }

  return { describePage };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = PopupStatus;
}
