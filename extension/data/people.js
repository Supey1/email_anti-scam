// people.js: DATA. Famous people whose names and faces scammers put on fake
// investment and crypto ads ("Elon Musk is giving away bitcoin", "Martin Lewis
// reveals his secret trading platform").
//
// core/text-rules.js uses this list only together with investing or crypto
// words AND an endorsement ("giving away", "reveals his secret", "recommends").
// A news story that just names one of them is not a warning sign.
// Full names only: a last name alone ("Musk", "Gates") is too often an ordinary word.

(function () {
  'use strict';
  const data = globalThis.GranblockData = globalThis.GranblockData || {};

  // Written the way the warning shows them. Matched without caring about capitals.
  const ENDORSERS = [
    'Elon Musk', 'Jeff Bezos', 'Bill Gates', 'Warren Buffett', 'Mark Zuckerberg', 'Mark Cuban',
    'Oprah Winfrey', 'Richard Branson', 'Martin Lewis', 'Kevin O\'Leary', 'Cathie Wood',
    'Michael Saylor', 'Vitalik Buterin', 'Tom Hanks', 'Dolly Parton', 'Taylor Swift',
    'Keanu Reeves', 'Gordon Ramsay', 'Jennifer Aniston', 'Steve Harvey', 'Dr. Phil',
    // TV shows used the same way ("as seen on Shark Tank")
    'Shark Tank', 'Dragons\' Den',
  ];

  data.people = { ENDORSERS };
  if (typeof module !== 'undefined') module.exports = data.people;
})();
