// services.js: DATA. Free personal email services, services that send email
// and count clicks for other businesses, and advertising networks.
//
// core/domain-rules.js uses them to tell "a newsletter sent the normal way" and
// "a real ad" apart from impersonation. Check each one before adding it.

(function () {
  'use strict';
  const data = globalThis.GranblockData = globalThis.GranblockData || {};

  // too, so they're never a sign of safety either. Check before adding.
  const EMAIL_SERVICES = [
    'sendgrid.net', 'mcsv.net', 'mcdlv.net', 'rsgsv.net', 'list-manage.com', 'mandrillapp.com',
    'amazonses.com', 'awstrack.me', 'sparkpostmail.com', 'mailgun.org', 'constantcontact.com', 'ccsend.com',
    'rs6.net', 'createsend.com', 'hubspotemail.net', 'klaviyomail.com', 'exacttarget.com', 'mktomail.com',
    'postmarkapp.com', 'sendinblue.com', 'govdelivery.com',
  ];


  // googleadservices.com" is normal and says nothing.
  const AD_NETWORKS = [
    'googleadservices.com', 'doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com', 'adnxs.com', 'criteo.com',
  ];


  // Free personal email services. A real company never emails you from one of these.
  const FREE_MAIL = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com',
    'msn.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
  ]);


  data.services = { EMAIL_SERVICES, AD_NETWORKS, FREE_MAIL };
  if (typeof module !== 'undefined') module.exports = data.services;
})();
