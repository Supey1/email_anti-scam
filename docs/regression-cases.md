# Regression cases

Scam and legitimate examples, the answer each should get, and the exact explanation the person reads.
Written from `tests/fixtures/regression/` by `node tests/regression.test.js --update`; don't edit by hand.

These examples were written by the people who wrote the rules, so passing them shows the rules work as
designed. They are NOT a measure of how many real scams the extension catches: that needs examples
nobody tuned the rules on.

| Verdict | Means |
|---|---|
| `warn` + `GO_BACK` / `DO_NOT_ENTER_INFO` | stopped: the person sees "Stop and check" before going on |
| `warn` + `VERIFY_INDEPENDENTLY` | noted: shown, never interrupts |
| `no_warning_signs` + `NONE` | nothing shown (which never means "safe") |
| `block` | known dangerous: no way through |

## delivery-fee

### 🛑 Scam: USPS "package on hold" email from a look-alike address with a redelivery fee

`delivery-fee/usps-redelivery-fee-email`, email. **Expected:** `warn` + `GO_BACK`. Fake USPS sender and website, a fee to release a package, and a deadline.

What the person reads:

- A link pretends to be the Post Office (USPS), but it goes to usps-redelivery.example, not the Post Office (USPS)'s real website. *(LOOKALIKE_DOMAIN)*
- This looks like an official notice from the Post Office (USPS), but it came from notice@usps-redelivery.example, not one of the Post Office (USPS)'s own email addresses. *(SENDER_NAME_MISMATCH)*
- The sender's address (notice@usps-redelivery.example) pretends to be the Post Office (USPS), but it isn't the Post Office (USPS)'s real address. *(LOOKALIKE_SENDER)*
- This email says it's from the Post Office (USPS), but none of its links go to the Post Office (USPS)'s real website (one goes to usps-redelivery.example). *(BRAND_NAME_MISMATCH)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It says a package couldn't be delivered or needs a fee. Fake delivery notices are a very common scam. Check the tracking number on the shipper's real website instead. *(DELIVERY_PROBLEM_CLAIM)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- It tries to rush you. Real companies give you time to think. *(PRESSURE_TACTICS)*

### 🛑 Scam: FedEx customs fee from a look-alike address, link to another website

`delivery-fee/fedex-customs-fee`, email. **Expected:** `warn` + `GO_BACK`. Look-alike FedEx sender, a fee to release a parcel, and links away from FedEx.

What the person reads:

- This looks like an official notice from FedEx, but it came from no-reply@fedex-delivery-support.example, not one of FedEx's own email addresses. *(SENDER_NAME_MISMATCH)*
- The sender's address (no-reply@fedex-delivery-support.example) pretends to be FedEx, but it isn't FedEx's real address. *(LOOKALIKE_SENDER)*
- This email says it's from FedEx, but none of its links go to FedEx's real website (one goes to fdx-customs.example). *(BRAND_NAME_MISMATCH)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It says a package couldn't be delivered or needs a fee. Fake delivery notices are a very common scam. Check the tracking number on the shipper's real website instead. *(DELIVERY_PROBLEM_CLAIM)*

### 🛑 Scam: Ad: USPS package on hold, pay the fee within 24 hours

`delivery-fee/ad-redelivery-fee`, link. **Expected:** `warn` + `GO_BACK`. Look-alike USPS address plus a fee and a deadline.

What the person reads:

- A link pretends to be the Post Office (USPS), but it goes to usps-redelivery.example, not the Post Office (USPS)'s real website. *(LOOKALIKE_DOMAIN)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It says a package couldn't be delivered or needs a fee. Fake delivery notices are a very common scam. Check the tracking number on the shipper's real website instead. *(DELIVERY_PROBLEM_CLAIM)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- The offer mentions the Post Office (USPS), but the link goes to usps-redelivery.example, not the Post Office (USPS)'s real website. *(BRAND_NAME_MISMATCH)*
- It tries to rush you. *(PRESSURE_TACTICS)*

### 🛑 Scam: USPS-branded payment page off USPS, card number sent elsewhere

`delivery-fee/redelivery-payment-page`, webpage. **Expected:** `warn` + `DO_NOT_ENTER_INFO`. A USPS payment page on someone else's website, sending the card number to a third website.

What the person reads:

- This page looks like a sign-in or payment page for the Post Office (USPS), but it is on usps-redelivery.example, not the Post Office (USPS)'s real website. *(FAKE_SIGN_IN_PAGE)*
- This website's name pretends to be the Post Office (USPS), but usps-redelivery.example is not the Post Office (USPS)'s real website. *(LOOKALIKE_DOMAIN)*
- What you type on this page would be sent to a different website (pay-portal.example). *(CREDENTIALS_SENT_ELSEWHERE)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It says a package couldn't be delivered or needs a fee. Fake delivery notices are a very common scam. Check the tracking number on the shipper's real website instead. *(DELIVERY_PROBLEM_CLAIM)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- It tries to rush you. *(PRESSURE_TACTICS)*

### ✅ Legitimate: Real UPS shipping notice from ups.com, tracking link on ups.com

`delivery-fee/ups-real-shipping`, email. **Expected:** `no_warning_signs` + `NONE`. Sent from UPS, links only to UPS, asks for nothing.

### ✅ Legitimate: Real USPS Informed Delivery digest

`delivery-fee/usps-informed-delivery-real`, email. **Expected:** `no_warning_signs` + `NONE`. Sent from USPS, links only to USPS.

### ✅ Legitimate: Amazon "your package was delivered" with an amazon.com link

`delivery-fee/amazon-delivered`, email. **Expected:** `no_warning_signs` + `NONE`. Sent from Amazon, links only to Amazon.

## fake-account-security

### 🛑 Scam: PayPal "account suspended" email from a look-alike address, link text shows paypal.com

`fake-account-security/paypal-suspended-lookalike`, email. **Expected:** `warn` + `GO_BACK`. Fake sender, look-alike address, a link that says paypal.com but goes elsewhere, and an account threat.

What the person reads:

- A link says it goes to paypal.com, PayPal's real website, but it really goes to paypa1-secure.example. *(HIDDEN_DESTINATION)*
- A link pretends to be PayPal, but it goes to paypa1-secure.example, not PayPal's real website. *(LOOKALIKE_DOMAIN)*
- This looks like an official notice from PayPal, but it came from alerts@paypa1-secure.example, not one of PayPal's own email addresses. *(SENDER_NAME_MISMATCH)*
- The sender's address (alerts@paypa1-secure.example) pretends to be PayPal, but it isn't PayPal's real address. *(LOOKALIKE_SENDER)*
- This email says it's from PayPal, but none of its links go to PayPal's real website (one goes to paypa1-secure.example). *(BRAND_NAME_MISMATCH)*
- It says something is wrong with your account. This is a common trick to get you to log in on a fake page. *(ACCOUNT_PROBLEM_CLAIM)*
- It tries to rush you. Real companies give you time to think. *(PRESSURE_TACTICS)*

### 🛑 Scam: "Microsoft account team" from a free Gmail account about an unusual sign-in

`fake-account-security/microsoft-signin-free-mail`, email. **Expected:** `warn` + `GO_BACK`. Microsoft never sends account alerts from a free personal email account.

What the person reads:

- The sender's name says Microsoft, but it came from a free personal email account (ms.account.team.alerts@gmail.com). Microsoft never does this. *(SENDER_NAME_MISMATCH)*
- This email says it's from Microsoft, but none of its links go to Microsoft's real website (one goes to secure-account-review.example). *(BRAND_NAME_MISMATCH)*
- It says something is wrong with your account. This is a common trick to get you to log in on a fake page. *(ACCOUNT_PROBLEM_CLAIM)*

### 🛑 Scam: Apple ID sign-in page on a free hosting website

`fake-account-security/apple-id-signin-free-hosting`, webpage. **Expected:** `warn` + `DO_NOT_ENTER_INFO`. A company sign-in page on a free website anyone can make, under a look-alike name.

What the person reads:

- This page looks like a sign-in or payment page for Apple, but it is on appleid-verify.netlify.app, not Apple's real website. *(FAKE_SIGN_IN_PAGE)*
- This website's name pretends to be Apple, but appleid-verify.netlify.app is not Apple's real website. *(LOOKALIKE_DOMAIN)*
- This page asks for a password or card number, but it's on appleid-verify.netlify.app, a free website anyone can make. Real banks and companies never do this. *(SIGN_IN_ON_FREE_HOSTING)*

### 🛑 Scam: Ad-style "account locked" text with a sign-in link to a free hosting website

`fake-account-security/wells-fargo-locked-link-free-hosting`, link. **Expected:** `warn` + `GO_BACK`. A bank name in a free-hosting address, a sign-in link there, and an account-problem story.

What the person reads:

- A link pretends to be Wells Fargo, but it goes to wellsfargo-secure.web.app, not Wells Fargo's real website. *(LOOKALIKE_DOMAIN)*
- A sign-in link goes to wellsfargo-secure.web.app, a free website anyone can make. Real banks and companies never put their sign-in pages there. *(SIGN_IN_ON_FREE_HOSTING)*
- It says your account or computer has a serious problem. *(ACCOUNT_PROBLEM_CLAIM)*
- The offer mentions Wells Fargo, but the link goes to wellsfargo-secure.web.app, not Wells Fargo's real website. *(BRAND_NAME_MISMATCH)*

### 🛑 Scam: Netflix "payment declined" from a look-alike address, link to another website

`fake-account-security/netflix-payment-declined-lookalike`, email. **Expected:** `warn` + `GO_BACK`. An account notice from an address that only imitates Netflix, linking away from Netflix.

What the person reads:

- This looks like an official notice from Netflix, but it came from billing@netflix-billing.example, not one of Netflix's own email addresses. *(SENDER_NAME_MISMATCH)*
- The sender's address (billing@netflix-billing.example) pretends to be Netflix, but it isn't Netflix's real address. *(LOOKALIKE_SENDER)*
- This email says it's from Netflix, but none of its links go to Netflix's real website (one goes to nflx-billing-update.example). *(BRAND_NAME_MISMATCH)*
- It says something is wrong with your account. This is a common trick to get you to log in on a fake page. *(ACCOUNT_PROBLEM_CLAIM)*

### 🛑 Scam: Chase sign-in page whose address starts with chase.com but belongs to someone else

`fake-account-security/chase-signin-official-domain-in-front`, webpage. **Expected:** `warn` + `DO_NOT_ENTER_INFO`. Writing chase.com in front of another website has no innocent use.

What the person reads:

- This website's address starts with chase.com, but it really belongs to secure-login.example, not Chase. *(LOOKALIKE_DOMAIN)*
- This page looks like a sign-in or payment page for Chase, but it is on chase.com.secure-login.example, not Chase's real website. *(FAKE_SIGN_IN_PAGE)*
- It says your account or computer has a serious problem. *(ACCOUNT_PROBLEM_CLAIM)*

## grandparent

### 🛑 Scam: Grandson arrested, needs bail in gift cards, don't tell mom

`grandparent/grandson-bail-gift-cards`, email. **Expected:** `warn` + `GO_BACK`. A family emergency, gift cards, and secrecy.

What the person reads:

- It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can't be gotten back. *(PAYMENT_METHOD_REQUEST)*
- It asks you to keep a secret. Real family and real companies don't ask that. *(SECRECY_REQUEST)*
- It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have. *(FAMILY_EMERGENCY)*

### 🛑 Scam: Grandchild in a hospital abroad needs a wire transfer, don't tell parents

`grandparent/grandpa-hospital-wire`, email. **Expected:** `warn` + `GO_BACK`. A family emergency, a wire transfer, and secrecy.

What the person reads:

- It asks you to keep a secret. Real family and real companies don't ask that. *(SECRECY_REQUEST)*
- It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have. *(FAMILY_EMERGENCY)*

### 🛑 Scam: "Hi Mom, new number, can you send money today"

`grandparent/hi-mom-new-number`, email. **Expected:** `warn` + `VERIFY_INDEPENDENTLY`. A "new number" plus a money request: check by calling the number you already have.

What the person reads:

- It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have. *(FAMILY_EMERGENCY)*
- It asks you to pay or send money. *(PAYMENT_DEMAND)*

### ✅ Legitimate: Grandchild thanks grandma for birthday money

`grandparent/grandchild-thank-you`, email. **Expected:** `no_warning_signs` + `NONE`. Money is mentioned, but nothing is asked for.

### ✅ Legitimate: Grandchild mentions a small accident, asks for nothing

`grandparent/grandchild-small-accident`, email. **Expected:** `no_warning_signs` + `NONE`. An accident, but no money request.

### ✅ Legitimate: Family member asks for a recipe

`grandparent/family-recipe-request`, email. **Expected:** `no_warning_signs` + `NONE`. Asks for a recipe, not money.

## legit-bank-notifications

### ✅ Legitimate: Chase payment confirmation from chase.com

`legit-bank-notifications/chase-payment-received`, email. **Expected:** `no_warning_signs` + `NONE`. From Chase, links only to Chase, asks for nothing.

### ✅ Legitimate: Wells Fargo statement-ready notice

`legit-bank-notifications/wells-fargo-statement`, email. **Expected:** `no_warning_signs` + `NONE`. From Wells Fargo, links only to Wells Fargo.

### ✅ Legitimate: Real Bank of America fraud alert ("did you make this purchase?")

`legit-bank-notifications/bofa-real-fraud-alert`, email. **Expected:** `no_warning_signs` + `NONE`. A real bank alert: sent from the bank, links only to the bank, and tells you to use the number on your card.

### ✅ Legitimate: PayPal "you received a payment" from paypal.com

`legit-bank-notifications/paypal-payment-received`, email. **Expected:** `no_warning_signs` + `NONE`. From PayPal, links only to PayPal.

### ✅ Legitimate: Chase "new sign-in" security alert from chase.com

`legit-bank-notifications/chase-new-signin`, email. **Expected:** `no_warning_signs` + `NONE`. Security wording, but from Chase with links only to Chase.

## legit-marketing

### ✅ Legitimate: Amazon deals newsletter from amazon.com

`legit-marketing/amazon-deals`, email. **Expected:** `no_warning_signs` + `NONE`. From Amazon, links only to Amazon.

### ✅ Legitimate: Small business sale sent through Mailchimp, with a deadline

`legit-marketing/small-business-mailchimp`, email. **Expected:** `no_warning_signs` + `NONE`. A deadline in a sale newsletter is ordinary marketing.

### ✅ Legitimate: Retailer newsletter: "Last chance, final hours"

`legit-marketing/final-hours-sale`, email. **Expected:** `no_warning_signs` + `NONE`. Marketing pressure alone isn't a scam sign.

### ✅ Legitimate: Restaurant: "Enter our giveaway to win a free dinner"

`legit-marketing/restaurant-giveaway`, email. **Expected:** `no_warning_signs` + `NONE`. A chance to win, not a claim that you already won.

### ✅ Legitimate: "PayPal Shopping" newsletter sent through an email service

`legit-marketing/paypal-shopping-via-service`, email. **Expected:** `no_warning_signs` + `NONE`. A newsletter through an email service: a company name there is normal.

## link-mismatch

### 🛑 Scam: Link text says www.chase.com, goes to chase-alerts.example

`link-mismatch/text-chase-goes-elsewhere`, link. **Expected:** `warn` + `GO_BACK`. Shows Chase's website, goes to an imitation.

What the person reads:

- A link says it goes to chase.com, Chase's real website, but it really goes to chase-alerts.example. *(HIDDEN_DESTINATION)*
- A link pretends to be Chase, but it goes to chase-alerts.example, not Chase's real website. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: Link text shows an irs.gov address, goes to tax-refund-portal.example

`link-mismatch/text-irs-goes-elsewhere`, link. **Expected:** `warn` + `GO_BACK`. Shows an official IRS address but goes somewhere else.

What the person reads:

- A link says it goes to irs.gov, the IRS's real website, but it really goes to tax-refund-portal.example. *(HIDDEN_DESTINATION)*

### 🛑 Scam: Email link written as www.paypal.com@pp-login.example

`link-mismatch/paypal-before-at`, email. **Expected:** `warn` + `GO_BACK`. Everything before "@" is decoration; the link really goes to pp-login.example.

What the person reads:

- A link is written to look like it goes to www.paypal.com, but it really goes to pp-login.example. *(MISLEADING_URL)*
- A link says it goes to paypal.com, PayPal's real website, but it really goes to pp-login.example. *(HIDDEN_DESTINATION)*

### 🛑 Scam: Google pass-through link that ends at a fake bank page

`link-mismatch/google-redirect-to-fake`, link. **Expected:** `warn` + `GO_BACK`. The pass-through is followed to where it really ends up: a look-alike bank address.

What the person reads:

- A link pretends to be Bank of America, but it goes to bankofamerica-alerts.example, not Bank of America's real website. *(LOOKALIKE_DOMAIN)*
- A link mentions Bank of America, but it goes to bankofamerica-alerts.example. *(BRAND_NAME_MISMATCH)*

### ✅ Legitimate: Link text shows the same website it goes to

`link-mismatch/text-matches-destination`, link. **Expected:** `no_warning_signs` + `NONE`. Shows and goes to the same website.

### ✅ Legitimate: Google pass-through link to the website its text shows

`link-mismatch/google-redirect-to-same`, link. **Expected:** `no_warning_signs` + `NONE`. The pass-through ends where the text says.

### ✅ Legitimate: Store newsletter link through an email-tracking service

`link-mismatch/newsletter-tracked-link`, email. **Expected:** `no_warning_signs` + `NONE`. Normal newsletters link through click-counting services.

### ✅ Legitimate: Link text with no website name, going to amazon.com

`link-mismatch/track-order-amazon`, link. **Expected:** `no_warning_signs` + `NONE`. Nothing to compare: the words don't name a website or company.

## lookalike-domains

### 🛑 Scam: Link to paypa1-secure.example with nothing else suspicious

`lookalike-domains/paypa1-alone`, link. **Expected:** `warn` + `VERIFY_INDEPENDENTLY`. A look-alike address alone is a warning sign, not proof: "check first", not a stop.

What the person reads:

- A link pretends to be PayPal, but it goes to paypa1-secure.example, not PayPal's real website. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: Link to paypal.com.account-verify.example

`lookalike-domains/paypal-in-front`, link. **Expected:** `warn` + `GO_BACK`. Writing paypal.com in front of another website has no innocent use.

What the person reads:

- A link's address starts with paypal.com, but it really belongs to account-verify.example, not PayPal. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: Link to "pаypal" spelled with a Cyrillic letter

`lookalike-domains/cyrillic-paypal`, link. **Expected:** `warn` + `GO_BACK`. Using another alphabet to imitate a company name has no innocent use.

What the person reads:

- A link uses letters from another alphabet to look like PayPal, but xn--pypal-4ve.example is not PayPal's real website. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: Link to amazom-deals.example

`lookalike-domains/amazom-misspelling`, link. **Expected:** `warn` + `VERIFY_INDEPENDENTLY`. A misspelled company name: a warning sign.

What the person reads:

- A link is a misspelling of Amazon: amazom-deals.example is not Amazon's real website. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: Sign-in page on rnicrosoft-login.example ("rn" looks like "m")

`lookalike-domains/rnicrosoft-signin`, webpage. **Expected:** `warn` + `DO_NOT_ENTER_INFO`. A Microsoft sign-in page on a look-alike address.

What the person reads:

- This page looks like a sign-in or payment page for Microsoft, but it is on rnicrosoft-login.example, not Microsoft's real website. *(FAKE_SIGN_IN_PAGE)*
- This website's name pretends to be Microsoft, but rnicrosoft-login.example is not Microsoft's real website. *(LOOKALIKE_DOMAIN)*

### 🛑 Scam: "Amazon" order email from arnazon-orders.example

`lookalike-domains/arnazon-sender`, email. **Expected:** `warn` + `GO_BACK`. A look-alike Amazon sender and website.

What the person reads:

- A link pretends to be Amazon, but it goes to arnazon-orders.example, not Amazon's real website. *(LOOKALIKE_DOMAIN)*
- The sender's address (orders@arnazon-orders.example) pretends to be Amazon, but it isn't Amazon's real address. *(LOOKALIKE_SENDER)*
- This email says it's from Amazon, but none of its links go to Amazon's real website (one goes to arnazon-orders.example). *(BRAND_NAME_MISMATCH)*
- The sender's name says Amazon, but the email address (orders@arnazon-orders.example) is not from Amazon. Companies sometimes send ads through other services, so this alone isn't proof. *(SENDER_NAME_MISMATCH)*

### ✅ Legitimate: Link to www.paypal.com

`lookalike-domains/real-paypal`, link. **Expected:** `no_warning_signs` + `NONE`. PayPal's real website.

### ✅ Legitimate: Link to amazon.co.uk

`lookalike-domains/real-amazon-uk`, link. **Expected:** `no_warning_signs` + `NONE`. Amazon's real UK website.

### ✅ Legitimate: Link to applebees.example (a restaurant, not Apple)

`lookalike-domains/applebees-not-apple`, link. **Expected:** `no_warning_signs` + `NONE`. "apple" inside a longer word is not an imitation.

### ✅ Legitimate: Link to chaseoutdoors.example (not Chase)

`lookalike-domains/chaseoutdoors-not-chase`, link. **Expected:** `no_warning_signs` + `NONE`. "chase" inside a longer word is not an imitation.

## prize-and-payment

### 🛑 Scam: Lottery "winnings" released after a wire-transfer fee, kept secret

`prize-and-payment/lottery-processing-fee`, email. **Expected:** `warn` + `GO_BACK`. A prize you never entered for, a fee to receive it, and a wire transfer.

What the person reads:

- It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can't be gotten back. *(PAYMENT_METHOD_REQUEST)*
- It asks you to keep a secret. Real family and real companies don't ask that. *(SECRECY_REQUEST)*
- It says you won something or are owed money. This is a very common scam. *(PRIZE_CLAIM)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*

### 🛑 Scam: Ad: "You have won a $2,000 gift card, claim before midnight"

`prize-and-payment/ad-gift-card-before-midnight`, link. **Expected:** `warn` + `GO_BACK`. A prize claim plus a deadline: a classic combination.

What the person reads:

- It promises you a prize or a reward. *(PRIZE_CLAIM)*
- It promises a prize AND rushes you. Together, these are a classic scam pattern. *(PRIZE_WITH_PRESSURE)*
- It tries to rush you. *(PRESSURE_TACTICS)*
- We could not confirm that claim-reward-now.example belongs to the company in this offer. *(UNVERIFIED_PRIZE_CLAIM)*

### 🛑 Scam: Web page: "You are our lucky winner, pay shipping to claim"

`prize-and-payment/lucky-winner-pay-shipping`, webpage. **Expected:** `warn` + `GO_BACK`. Prize plus a fee to receive it plus a deadline.

What the person reads:

- It promises you a prize or a reward. *(PRIZE_CLAIM)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It promises a prize AND rushes you. Together, these are a classic scam pattern. *(PRIZE_WITH_PRESSURE)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- It tries to rush you. *(PRESSURE_TACTICS)*

### 🛑 Scam: "Pastor" asks for gift cards from a free email account, secretly

`prize-and-payment/pastor-gift-cards`, email. **Expected:** `warn` + `GO_BACK`. Gift cards plus secrecy. Real pastors and bosses don't ask for gift card codes by email.

What the person reads:

- It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can't be gotten back. *(PAYMENT_METHOD_REQUEST)*
- It asks you to keep a secret. Real family and real companies don't ask that. *(SECRECY_REQUEST)*

### 🛑 Scam: Investment pitch: send bitcoin today to double it

`prize-and-payment/crypto-double-your-money`, email. **Expected:** `warn` + `GO_BACK`. Paying with crypto plus pressure.

What the person reads:

- It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can't be gotten back. *(PAYMENT_METHOD_REQUEST)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- It tries to rush you. Real companies give you time to think. *(PRESSURE_TACTICS)*
- It asks you to pay or send money. *(PAYMENT_DEMAND)*

### 🛑 Scam: Sweepstakes page asking for a gift card to release the prize

`prize-and-payment/sweepstakes-gift-card-fee`, webpage. **Expected:** `warn` + `GO_BACK`. Prize, payment by gift card, and a countdown.

What the person reads:

- It promises you a prize or a reward. *(PRIZE_CLAIM)*
- It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don't work this way. *(PAY_TO_CLAIM)*
- It promises a prize AND rushes you. Together, these are a classic scam pattern. *(PRIZE_WITH_PRESSURE)*
- It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have. *(URGENT_PAYMENT_REQUEST)*
- It tries to rush you. *(PRESSURE_TACTICS)*

### ✅ Legitimate: Store confirms you entered its giveaway (no win, no payment)

`prize-and-payment/real-giveaway-entry-confirmation`, email. **Expected:** `no_warning_signs` + `NONE`. No claim that you won, no payment asked.

### ✅ Legitimate: News story link about someone else winning the lottery

`prize-and-payment/news-lottery-winner`, link. **Expected:** `no_warning_signs` + `NONE`. Talks about a lottery but promises the reader nothing.

## security-awareness

### ✅ Legitimate: Consumer guide on recognizing phishing, quoting scam phrases

`security-awareness/phishing-guide-page`, webpage. **Expected:** `no_warning_signs` + `NONE`. Talks about scams; asks the reader for nothing.

### ✅ Legitimate: Article explaining the grandparent scam

`security-awareness/grandparent-scam-article`, webpage. **Expected:** `no_warning_signs` + `NONE`. Describes the scam to warn readers.

### ✅ Legitimate: Chase newsletter: we will never ask for your password or gift cards

`security-awareness/bank-scam-newsletter`, email. **Expected:** `no_warning_signs` + `NONE`. Scam words, but explaining them, from the bank, linking to the bank.

### ✅ Legitimate: Community newsletter: scam alert quoting scam lines

`security-awareness/senior-center-scam-alert`, email. **Expected:** `no_warning_signs` + `NONE`. Quotes scam lines to warn readers.

### ✅ Legitimate: Wells Fargo security center page on wellsfargo.com

`security-awareness/bank-security-center`, webpage. **Expected:** `no_warning_signs` + `NONE`. The bank's own website.

### ✅ Legitimate: News story quoting a fake virus pop-up

`security-awareness/tech-scam-news-story`, webpage. **Expected:** `no_warning_signs` + `NONE`. Quotes a scam to warn readers.

## tech-support

### 🛑 Scam: Fake virus pop-up telling you to call a number and not close the page

`tech-support/virus-popup-call-number`, webpage. **Expected:** `warn` + `GO_BACK`. A device scare plus "call this number": how tech-support scams work.

What the person reads:

- It says your account or computer has a serious problem. *(ACCOUNT_PROBLEM_CLAIM)*
- It tells you to call a phone number, or not to close the page. Real security warnings never do this. *(CALL_THIS_NUMBER)*
- It tries to rush you. *(PRESSURE_TACTICS)*

### 🛑 Scam: "Norton" renewal for $399.99 from a free account: call to cancel

`tech-support/subscription-renewal-refund`, email. **Expected:** `warn` + `GO_BACK`. The "refund" scam: a surprise charge, a phone number to cancel, a deadline, from a free account.

What the person reads:

- It says you were charged for something and gives a phone number to cancel or get a refund. This is how "refund" scams start. Don't call: check your bank or card statement yourself. *(UNEXPECTED_CHARGE)*
- The sender says it is a company or department, but it uses a free personal email address (billing.dept.norton@gmail.com). *(COMPANY_ON_FREE_EMAIL)*
- It tries to rush you. Real companies give you time to think. *(PRESSURE_TACTICS)*

### 🛑 Scam: "Microsoft Support" from another company's address asking for remote access

`tech-support/microsoft-remote-access`, email. **Expected:** `warn` + `GO_BACK`. Microsoft doesn't email about infections, and remote access lets a scammer take over the computer.

What the person reads:

- This looks like an official notice from Microsoft, but it came from support@ms-helpdesk.example, not one of Microsoft's own email addresses. *(SENDER_NAME_MISMATCH)*
- It talks about computer viruses or "tech support." Real companies won't contact you this way. *(TECH_SUPPORT_CLAIM)*

### 🛑 Scam: Ad: "Your PC may be at risk, call technicians now"

`tech-support/pc-at-risk-ad`, link. **Expected:** `warn` + `GO_BACK`. A device scare plus a phone number in an ad.

What the person reads:

- It says your account or computer has a serious problem. *(ACCOUNT_PROBLEM_CLAIM)*
- It tells you to call a phone number, or not to close the page. Real security warnings never do this. *(CALL_THIS_NUMBER)*
- The offer mentions Microsoft, but the link goes to pc-repair-help.example, not Microsoft's real website. *(BRAND_NAME_MISMATCH)*

### ✅ Legitimate: Help article on removing malware

`tech-support/malware-removal-article`, webpage. **Expected:** `no_warning_signs` + `NONE`. Advice about scams, asking nothing of the reader.

### ✅ Legitimate: Real AppleCare receipt from apple.com

`tech-support/applecare-receipt`, email. **Expected:** `no_warning_signs` + `NONE`. Sent from Apple, links only to Apple.
