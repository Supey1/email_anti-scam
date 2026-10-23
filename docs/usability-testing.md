# Usability testing with older adults

**Status: no sessions have been run yet.** This is the plan, the scenarios, and the tools to record and score them. Nothing in `docs/usability-findings.md` is a finding until a person has actually done a session.

## Safety and consent (read first)

- Every scenario is **simulated**. Use only the practice pages and `tests/fake-gmail.html`, with no real personal email account, and **no live scam links**. Tell participants this before they start, and again whenever a scenario looks alarming.
- Say that the test is of the software, not of them, and that they can stop at any time without giving a reason.
- Record no names, account details, or photos of screens showing personal information. Use a participant code (P01, P02, ...). Keep the notes sheet private.
- This is a school or competition project: check the rules of the Congressional App Challenge and your school about testing with people (parent or guardian consent when team members are minors, adult supervision, how notes may be stored) before the first session.
- Offer a short, friendly debrief about how to spot real scams, because the sessions will have shown them some.

## Setup

1. Load the extension (`README.md`, "Try it") with the default settings, and choose **Check all websites and Gmail** on the welcome page (Chrome asks once). Large text is the default.
2. Serve the pages: `python3 -m http.server 8000` inside `tests/pages`, and open `tests/fake-gmail.html` directly in Chrome for the email scenarios (it loads the extension's code itself).
3. Use the same Chrome window for everyone. Reset settings (Settings, "Put every setting back the way it was") between participants.
4. Run the scenarios in a **different order for each participant** so one confusing scenario does not colour the next.

## Procedure for each scenario (about 2 minutes)

Say: "Pretend this is your own computer. Take a look at this and tell me what you would do, thinking out loud." Do not explain the warning. If they ask what something means, note it ("needed help"), then answer.

Ask afterwards, in this order:
1. "In your own words, what is this telling you?"
2. "Why do you think it appeared?"
3. "What would you do next?"

Write down where they pause, re-read, reach for the wrong button, or say something that does not match what the warning actually said.

## The scenarios (start with 15 to 20)

"Good answer" is what the participant should say or do. Expected verdicts come from the current build: "Danger" is only for known dangerous websites; strong signs are "Caution: Stop and check this first"; weaker ones are "Be careful", which never interrupts.

| ID | Open | What is simulated | Expected verdict | A good answer |
|---|---|---|---|---|
| U01 | fake-gmail, **Fake PayPal** | Scam email from a look-alike address | Caution (Stop and check) | Says it is a scam or fake PayPal; would not click or reply; would call PayPal using a number they know, or ask someone |
| U02 | fake-gmail, **Grandparent scam** | Relative asks for gift cards and secrecy | Caution (Stop and check) | Would not send gift cards; would phone the relative on a known number |
| U03 | fake-gmail, **Shipping (be careful)** | Delivery notice with a shortened link | Be careful | Would not click; would check the tracking on the carrier's real site |
| U04 | fake-gmail, **Normal email** | Lunch invitation | No warning signs | Reads it normally; does not panic. Note whether they treat "no warning signs" as "definitely safe" |
| U05 | fake-gmail, **Fake bank (hidden link)**, then click the link | Link text says one site, goes to another | Caution (Stop and check), then the click is stopped | Understands the link is not really the bank's; chooses "Go back to safety" |
| U06 | fake-gmail, **Delivery from UPS (real)** | A real notice from UPS's own address | No warning signs | Reads it normally. Note whether they still check the tracking on UPS's real website |
| U07 | fake-gmail, **Doctor reminder** | Real reminder that says "immediately" (a known false alarm) | Be careful | Understands this is a weak warning and that calling the clinic on a known number settles it |
| U08 | fake-gmail, **Lottery win** | Prize that asks for a gift card fee | Caution (Stop and check) | Recognises the "pay to receive a prize" trick |
| U09 | fake-gmail, **Shared invoice (hard)** | A polished phishing email the tool does not catch | No warning signs | Notes whether the person is more careful than the tool: "no warning signs" must not make them stop thinking |
| U10 | `fake-login.html` | Fake PayPal login | Caution (Stop and check card appears) | Would not type a password; can say why |
| U11 | `fake-login.html`, click **Verify your PayPal account now** | Link to a look-alike address | Warning page | Chooses "Go back to safety" |
| U12 | `fake-ad.html`, click the prize ad | Prize advertisement | Warning page | Would not claim the prize; says "too good to be true" or "it wants me to hurry" |
| U13 | `fake-ad.html`, click the **shoes** ad | An ordinary ad that goes through an ad tracker | Opens normally | Not slowed down. (Before the branches were merged this was a false alarm.) |
| U14 | `fake-legitimate.html` | Normal page full of scary words | No card | Browses normally and does not feel anything is wrong |
| U15 | `fake-legitimate.html`, click **Donate with PayPal** | Real link that must work | Opens normally | Not slowed down |
| U16 | `click-guard.html`, click **Open your statement** | Known dangerous address | Danger, no way past | Understands it cannot be opened; chooses to go back |
| U17 | `fake-form.html` over plain http from another computer (Chrome treats `localhost` as secure, so the card won't appear there) | Card form to another site | Caution (Stop and check) | Would not enter a card number |
| U18 | Popup | "Is this page being checked?" | n/a | Can say whether protection is on and what to do to get help, without help |
| U19 | Settings page | Make the text larger and turn on reading aloud | n/a | Finds and changes both |
| U20 | Any warning | Press **Read to me** | n/a | Finds it, understands what it does, can stop it |

## Recording and scoring

Fill one row per participant per scenario in a copy of `tests/usability/results-template.csv`:

| Column | Meaning |
|---|---|
| `understood_verdict` | 1 if they understood how worried to be (danger, caution, or nothing found), else 0 |
| `reason_accuracy` | 0 reason wrong, 1 partly right, 2 right, judged against what the warning actually said |
| `next_step_appropriate` | 1 if what they said they would do suits the scenario (see "A good answer"), else 0 |
| `needed_help` | 1 if they asked for an explanation or needed a hint |
| `seconds_to_decision` | Roughly, from the warning appearing to their answer |
| `hesitation_notes`, `misunderstanding_notes` | Their words and what you saw |

Then run `node tests/usability-score.js your-results.csv`. It prints **usability success** (understood AND chose an appropriate next step AND needed no help), the share who understood, how often the reason was right, how often help was needed, the hardest scenarios first, and every note.

A scenario where several people hesitate, need help, or misunderstand is a candidate for an interface change. Record each change in `docs/usability-findings.md` with the evidence that prompted it, then re-test that scenario with new participants.
