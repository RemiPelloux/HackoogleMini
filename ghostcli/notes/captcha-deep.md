# `/gc.js` — deep read of FCaptcha 1.21.0

122 280 bytes, unminified, MIT, self-hosted at the apex. Everything below is read from the published
file; no request was sent to `/gc/*`.

## 1. Module map

| class | line | role |
|---|---|---|
| `BehavioralCollector` | 25 | pointer kinematics: micro-tremor, velocity variance, exploration ratio, overshoot corrections, straight-line ratio, click precision |
| `SensorCollector` | 759 | device motion/orientation |
| `FormAnalyzer` | 841 | keystroke timing (textareas only), typing *modality*, form-submit interception |
| `EnvironmentalCollector` | 1223 | `webdriver`, automation flags, CDP probes (`_detectCDP`, `_detectCDPRuntime`), headless indicators, WebGL renderer, fonts, memory/cores |
| `PoWManager` | 2228 | SHA-256 proof of work, Web Worker pool, nonce striding |
| `TemporalCollector` | 2490 | `performance.now()` deltas, event variance, interaction duration |
| `CaptchaWidget` | 2570 | visual widget, orchestrates the six collectors |
| `InvisibleSession` | 2918 | hands-free mode: continuous collection + `/api/score` |

## 2. Protocol

```
GET  /gc/api/pow/challenge?siteKey=ghostcli   → {challengeId, prefix, difficulty, expiresAt}
POST /gc/api/verify                           → {siteKey, signals, signalsJson, powSolution{challengeId,nonce,hash,signalsHash}, powTiming}
POST /gc/api/score                             (InvisibleSession, continuous)
POST /api/chat   header  x-gc-verify: <token>  ← consumer side
POST /api/auth/login  body  capToken: <token>   ← consumer side
```

Server-issued challenges carry `challengeId`, so when `/gc` is healthy the proof really is bound to a
server nonce. That is the correct design and it deserves saying before the criticism.

## 3. The scoring model, with their own weights

The client-side verdict is `passed = score < 0.5`, and the weights are published in the file:

| signal | weight |
|---|---|
| no pointer path at all (`totalPoints<5 && trajectory<10`) | **0.35** |
| `navigator.webdriver === true` | **0.25** |
| headless without outer dimensions | 0.12 |
| micro-tremor < 0.2 | 0.12 |
| velocity variance < 0.03 | 0.10 |
| WebGL "suspicious renderer" | 0.10 |
| PoW duration < 50 ms | 0.10 |
| straight-line ratio > 0.8 | 0.08 |
| exploration ratio < 0.05, event delta variance < 3 | 0.08 each |
| `plugins === 0`, `innerEqualsOuter`, click precision < 2, no overshoot | 0.05 each |

Two arithmetic consequences, straight from their numbers:

**N1 — `navigator.webdriver` alone does not fail you.** 0.25 < 0.5. Add zero plugins (0.05) and
`innerEqualsOuter` (0.05) and you are at 0.35. A blatantly automated browser still passes unless a
*second* class of heuristic fires. The most reliable single automation signal in the platform is
weighted at half the threshold.

**N2 — it is really a pointer-kinematics test.** 0.35 + 0.12 + 0.10 + 0.08 + 0.06 lives in mouse
behaviour. Everything else is decoration. The header's claim of detecting "vision AI agents" is
marketing: there is no vision anywhere in the file, only the assumption that synthetic pointer paths
are straighter and less jittery than human ones.

## 4. False positives the weights create

- **Software/VM rendering fails.** `webglInfo.suspiciousRenderer` penalises SwiftShader, llvmpipe,
  remote desktops, VDI, and privacy browsers that randomise or disable WebGL (0.10).
- **`plugins === 0`** is a heuristic from an era when Flash existed. Current Chrome and Firefox
  routinely report zero plugins — 0.05 charged to every modern user.
- **Touch users need ≥ 3 touch events** to be exempted from the zero-pointer penalty. A phone user
  who scrolls twice and taps once collects 0.35 and can fail on a screen that never had a mouse.
- Credit where due: `isKbdUser` exempts keyboard-only navigation (`keyEvents>0 && totalPoints===0`),
  so screen-reader and keyboard users are consciously handled. That is more than most homegrown
  bot checks do.

## 5. Fail-open paths — the structural weakness

Three places where the *security verdict* falls back to the trusting side:

```js
// 1. no serverUrl → never talks to a server
if (!FCaptcha.serverUrl) return this._clientSideVerify(signals);

// 2. any network error → same
} catch (error) {
  console.warn('Server unavailable, using client-side verification');
  return this._clientSideVerify(signals);
}

// 3. challenge fetch failure → local challenge, self-chosen id/prefix/difficulty
_generateLocalChallenge() { … local: true }
```

And what `_clientSideVerify` hands back on success:

```js
token: passed ? btoa(JSON.stringify({ timestamp: Date.now(), score, id: this.id })) : null
```

An **unsigned base64 blob asserting its own score**. In production `serverUrl:"/gc"` is configured, so
path 1 is dormant — but paths 2 and 3 are one flaky `/gc` away, and this deployment has measured
65-second stalls and `429`s (F18). The client cannot distinguish "your score is bad" from "I could
not reach the server", and it chooses the answer that lets you through.

**The single question a triage team must ask:** does the server accept a token whose shape it did not
sign, and does it reject `local: true` challenges? If yes to the second and the token is HMAC'd
server-side, this is all fine and the fallback is harmless. If it does not know the difference, the
control is advisory. I have not tested it, and testing it means forging verifications.

## 6. Global side effects worth a bug report on their own

```js
_interceptFormSubmit() {
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () { self._recordProgrammaticSubmit(this); … };
}
```

A captcha library **monkey-patches a platform prototype globally**. Loaded on the login page, the
patch persists for the page's lifetime, is not restored, and composes badly with any other library
that patches the same method (analytics, form validation, test runners). Same shape for the `submit`
listener registered with `capture: true` at document level.

## 7. Privacy, fairly assessed

Credit first: the file is careful, and comments say so — textarea keystroke analysis is scoped to
`TEXTAREA` deliberately ("safe from password manager conflicts"), and the document-level typing
modality tracking records only *how* text arrived (paste shortcut Meta vs Ctrl, input events without
keydowns, missing `inputType`), explicitly "never what or where… safe to run across every field
including password inputs a password manager fills". **No field values, no key codes, no content.**

What remains is still a lot: pointer kinematics, typing cadence, `deviceMemory`, `hardwareConcurrency`,
font list, WebGL renderer, timezone, language, screen and viewport metrics, media devices, sensor
readings — transmitted to `/gc/api/verify` and analysed server-side to make a decision about the
person. Fingerprint + behavioural biometrics. Under LGPD (operator is Brazilian) and GDPR (sold
internationally) that is personal data requiring a lawful basis, transparent notice and a DPIA — and
the app ships **no consent surface at all**. No retention statement is visible either, and the
`/gc/api/score` endpoint implies the profile is kept, not just scored once.

## 8. Versions and provenance

`version: '1.21.0'`, with a comment to keep it in sync with `server-node/package.json` and
`server-python/server.py` — so the vendor ships both a Node and a Python verification backend, and the
copy served here is one specific release. Unminified production JS on an 18-day-old domain means the
entire detection model, including the weights above, is public. For a bot-detection product that is
self-defeating; for a reviewer it is a gift.

## 9. Summary

| id | finding | severity |
|---|---|---|
| N1 | `navigator.webdriver` (0.25) below the 0.5 pass threshold — automation signal weighted at half | Medium |
| N2 | Detection is pointer kinematics; "vision AI agent" claim unsupported by the code | Info |
| N3 | Fail-open: no serverUrl, network error, or challenge failure → client-trusted unsigned token | Medium (High if the server accepts it) |
| N4 | `btoa(JSON)` self-asserted score token, no signature, in the fallback path | Medium |
| N5 | `HTMLFormElement.prototype.submit` monkey-patched globally, never restored | Low |
| N6 | False-positive classes: software/VM WebGL, `plugins===0`, touch users below 3 events | Low |
| N7 | Fingerprint + behavioural biometrics with no consent surface (LGPD/GDPR) | Medium |
| N8 | Unminified detection model published — all thresholds/weights public | Low |

Everything above is inference from the shipped file. The behaviour of `/gc/api/verify` — whether it
validates signatures, rejects `local:true`, and enforces difficulty server-side — is the part that
decides how much of this matters, and it is exactly the part I did not probe.
