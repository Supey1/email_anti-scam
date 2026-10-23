// status.js: the popup's plain answer to "is this page being checked?"
// Pure function: what the extension knows goes in, words come out.
//   protectionEnabled  the on/off switch (settings)
//   access             'all' | 'gmail' | 'none': the website access the person has given (GET_STATUS)
//   url                the tab's address
//   reply              what the page's checker said when asked (undefined if it didn't answer)

const PopupStatus = (() => {
  const no = (text, detail, openSettings = false) => ({ state: 'no', icon: '⛔', text, detail, openSettings });
  const NOT_SURE = { state: 'unknown', icon: '❔', text: 'Not sure yet.', detail: 'Reload this page to start checking it.', openSettings: false };

  function describePage({ protectionEnabled, access, url, reply }) {
    let parsed = null;
    try { parsed = url ? new URL(url) : null; } catch (e) { parsed = null; }

    if (!protectionEnabled) return no('No, this page is not being checked.', 'Protection is turned off.');
    // Without website access Chrome does not tell us the page's address at all.
    if (!url && access === 'none') return no('No, this website is not being checked.', 'You have not allowed website access yet. Open Settings to allow it.', true);
    if (!parsed || !/^https?:$/.test(parsed.protocol)) return no('This page cannot be checked.', 'Chrome does not let extensions look at this kind of page.');

    if (parsed.hostname === 'mail.google.com') {
      if (access !== 'all' && access !== 'gmail') return no('No, Gmail emails are not being checked.', 'You have not allowed website access yet. Open Settings to allow it.', true);
      return reply && reply.checking
        ? { state: 'yes', icon: '✅', text: 'Yes. Emails you open in Gmail are being checked.', detail: 'This happens on this computer. Nothing is sent anywhere.', openSettings: false }
        : NOT_SURE;
    }

    if (access === 'none') return no('No, this website is not being checked.', 'You have not allowed website access yet. Open Settings to allow it.', true);
    if (access === 'gmail') return no('No, this website is not being checked.', 'You chose to check only Gmail. Open Settings to change that.', true);
    return reply && reply.checking
      ? { state: 'yes', icon: '✅', text: 'Yes, this page is being checked.', detail: 'We look at its words, links, and forms on this computer. Nothing is sent anywhere.', openSettings: false }
      : NOT_SURE;
  }

  return { describePage };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = PopupStatus;
}
