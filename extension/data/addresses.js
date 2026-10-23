// addresses.js: DATA about web addresses. Website endings shared by many
// owners (a hand-picked part of the Public Suffix List), free hosting sites,
// link shorteners, risky endings, and look-alike letters from other alphabets.
//
// core/url-normalizer.js and core/url-rules.js use them. If a check gets a
// country or a host wrong, the fix is usually here.

(function () {
  'use strict';
  const data = globalThis.GranblockData = globalThis.GranblockData || {};

  // Website endings with more than one part, where everything just in front
  // belongs to a different owner: "bbc.co.uk" and "evil.co.uk" are unrelated.
  // This is a hand-picked part of the Public Suffix List (publicsuffix.org),
  // covering common countries and the free hosting sites scammers use most.
  // If a check gets a country or host wrong, add its ending here.
  const COUNTRY_ENDINGS = [
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk', 'police.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.za', 'org.za', 'gov.za', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'go.kr',
    'com.br', 'net.br', 'org.br', 'gov.br', 'com.mx', 'org.mx', 'gob.mx', 'com.ar', 'gob.ar', 'com.co', 'com.pe',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'gov.sg', 'edu.sg', 'com.my', 'com.ph',
    'co.id', 'or.id', 'go.id', 'ac.id', 'co.th', 'go.th', 'in.th', 'com.vn', 'gov.vn',
    'com.tr', 'gov.tr', 'co.il', 'org.il', 'gov.il', 'com.sa', 'com.eg', 'com.ng', 'gov.ng', 'com.pk', 'co.ke', 'com.ua', 'gov.ua',
  ];

  // Free hosting: anyone can make a website under these in minutes, so
  // scammers do. A real bank never has its sign-in page on one.
  const FREE_HOSTING = new Set([
    'github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'square.site',
    'netlify.app', 'vercel.app', 'herokuapp.com', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'appspot.com', 'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com', 'glitch.me', 'ngrok.io',
    'ngrok-free.app', 'onrender.com', 'fly.dev', 'surge.sh', '000webhostapp.com', 'duckdns.org',
    'myshopify.com', 'webflow.io', 'godaddysites.com', 'carrd.co', 'notion.site',
  ]);

  // Look-alike letters from other alphabets, and the plain letter each imitates.
  const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
    'һ': 'h', 'ӏ': 'l', 'ո': 'n', 'ս': 'u',
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'ε': 'e',
    'ı': 'i', 'ł': 'l', 'ø': 'o', 'ß': 'ss',
  };

  // Link shorteners hide where a link really goes.
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
  ]);


  // Website endings that are cheap and often used by scam sites.
  const RISKY_ENDINGS = new Set(['xyz', 'top', 'click', 'zip', 'mov', 'icu', 'buzz', 'cfd', 'sbs', 'rest', 'lol']);

  data.addresses = { COUNTRY_ENDINGS, FREE_HOSTING, SHORTENERS, RISKY_ENDINGS, CONFUSABLES };
  if (typeof module !== 'undefined') module.exports = data.addresses;
})();
