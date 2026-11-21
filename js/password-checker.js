/*
 * SecurePass - password-checker.js
 * --------------------------------
 * Pure analysis logic. No DOM access, no network, no storage, no logging.
 * The password only ever exists as a function argument in memory.
 *
 * How the score works (high level):
 *   1. Work out the "character pool" the password draws from (a-z, A-Z, 0-9, symbols).
 *   2. Raw entropy  = length x log2(pool size).
 *   3. Find predictable parts (common words, keyboard walks, sequences, repeats, years).
 *      Each predictable part is charged a small fixed cost instead of full entropy.
 *   4. Effective entropy = sum of those costs + full cost for all remaining characters.
 *   5. Score (0-100) = effective entropy in bits (100 bits maps to 100 points),
 *      then caps are applied for very short, short or commonly-used passwords.
 */
(function (global) {
  'use strict';

  /* ---------- Strength levels (as required by the project brief) ---------- */
  const LEVELS = [
    { min: 0,  max: 19,  key: 'very-weak',   label: 'Very Weak'   },
    { min: 20, max: 39,  key: 'weak',        label: 'Weak'        },
    { min: 40, max: 59,  key: 'medium',      label: 'Medium'      },
    { min: 60, max: 79,  key: 'strong',      label: 'Strong'      },
    { min: 80, max: 100, key: 'very-strong', label: 'Very Strong' }
  ];

  /* ---------- Small built-in lists (kept offline on purpose) ---------- */
  const COMMON_PASSWORDS = new Set([
    '123456', '123456789', '12345678', '12345', '1234567', '1234567890', '111111', '000000',
    '123123', '654321', '666666', '121212', '112233', '987654321', '123321', '159753',
    'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', 'p@ssword', 'pass', 'pass123',
    'qwerty', 'qwerty123', 'qwertyuiop', 'qwerty1', 'asdfgh', 'asdfghjkl', 'zxcvbnm', '1q2w3e4r',
    '1qaz2wsx', 'qazwsx', 'abc123', 'abcd1234', 'abcdef', 'abcdefg', 'abc12345',
    'iloveyou', 'ilovegod', 'admin', 'admin123', 'administrator', 'root', 'toor', 'login', 'welcome',
    'welcome1', 'welcome123', 'letmein', 'monkey', 'dragon', 'master', 'shadow', 'sunshine',
    'princess', 'football', 'baseball', 'soccer', 'hockey', 'superman', 'batman', 'trustno1',
    'hello', 'hello123', 'freedom', 'whatever', 'qazwsxedc', 'michael', 'jordan', 'charlie',
    'donald', 'secret', 'changeme', 'default', 'guest', 'test', 'test123', 'testing', 'user',
    'summer', 'winter', 'spring', 'autumn', 'google', 'facebook', 'india123', 'cricket', 'krishna',
    'sachin', 'rockyou', 'starwars', 'pokemon', 'naruto', 'computer', 'internet', 'killer',
    'mustang', 'access', 'flower', 'hottie', 'loveme', 'zaq12wsx', 'biteme', 'ashley', 'bailey'
  ]);

  // Words that are too predictable to count as real entropy when found inside a password.
  const COMMON_WORDS = [
    'password', 'passwd', 'pass', 'qwerty', 'admin', 'welcome', 'login', 'letmein', 'iloveyou',
    'monkey', 'dragon', 'master', 'shadow', 'sunshine', 'princess', 'football', 'baseball',
    'secret', 'hello', 'love', 'freedom', 'whatever', 'computer', 'internet', 'summer', 'winter',
    'spring', 'autumn', 'google', 'facebook', 'cricket', 'india', 'user', 'test', 'root', 'guest',
    'changeme', 'default', 'superman', 'batman', 'starwars', 'pokemon', 'naruto', 'killer',
    'mustang', 'flower', 'michael', 'jordan', 'charlie', 'monday', 'friday', 'sunday'
  ];

  const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qazwsxedc', '!@#$%^&*()'];

  // "Leet speak" substitutions that attackers try automatically (p@ssw0rd -> password).
  const LEET_VARIANTS = [
    { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '8': 'b' },
    { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'l', '8': 'b' }
  ];

  const SYMBOL_POOL = 33;      // printable ASCII symbols (incl. space)
  const OTHER_POOL = 32;       // allowance for non-ASCII characters
  const MAX_SCORE_BITS = 100;  // 100 bits of effective entropy = 100 points
  const GUESSES_PER_SECOND = 1e10; // assumed offline attacker against a fast hash

  /* ---------- Helpers ---------- */

  function getLevel(score) {
    for (let i = 0; i < LEVELS.length; i++) {
      if (score >= LEVELS[i].min && score <= LEVELS[i].max) return LEVELS[i];
    }
    return LEVELS[LEVELS.length - 1];
  }

  function describeCharacters(pw) {
    const info = { lower: false, upper: false, digit: false, symbol: false, other: false };
    for (const ch of pw) {
      if (ch >= 'a' && ch <= 'z') info.lower = true;
      else if (ch >= 'A' && ch <= 'Z') info.upper = true;
      else if (ch >= '0' && ch <= '9') info.digit = true;
      else if (ch.charCodeAt(0) < 128) info.symbol = true;
      else info.other = true;
    }
    return info;
  }

  function poolSize(info) {
    let pool = 0;
    if (info.lower) pool += 26;
    if (info.upper) pool += 26;
    if (info.digit) pool += 10;
    if (info.symbol) pool += SYMBOL_POOL;
    if (info.other) pool += OTHER_POOL;
    return pool;
  }

  function isAlnum(ch) {
    return /^[a-z0-9]$/.test(ch);
  }

  function normalizeLeet(lower, map) {
    let out = '';
    for (const ch of lower) out += map[ch] || ch;
    return out;
  }

  function isCommonPassword(pw) {
    const lower = pw.toLowerCase();
    const candidates = [lower].concat(LEET_VARIANTS.map(function (m) { return normalizeLeet(lower, m); }));
    for (const c of candidates) {
      if (COMMON_PASSWORDS.has(c)) return true;
      // "password123!" is just "password" with a decoration on the end.
      const stripped = c.replace(/[0-9!@#$%^&*._\-]+$/, '');
      if (stripped.length >= 4 && COMMON_PASSWORDS.has(stripped)) return true;
    }
    return false;
  }

  /* ---------- Pattern detection ---------- */
  // Each finder returns matches: { start, end (exclusive), type, label, cost (bits) }

  function findRepeats(pw, bpc) {
    const matches = [];
    // Same character repeated 3+ times: "aaaa", "1111"
    const runRe = /(.)\1{2,}/gu;
    let m;
    while ((m = runRe.exec(pw)) !== null) {
      const len = m[0].length;
      matches.push({ start: m.index, end: m.index + len, type: 'repeat',
        label: 'repeated character run', cost: bpc + Math.log2(len) });
    }
    // Repeated blocks of 2-6 characters: "abcabc", "xyxyxy"
    const blockRe = /(.{2,6}?)\1+/gu;
    while ((m = blockRe.exec(pw)) !== null) {
      const unit = m[1].length;
      const times = m[0].length / unit;
      matches.push({ start: m.index, end: m.index + m[0].length, type: 'repeat',
        label: 'repeated block', cost: unit * bpc + Math.log2(times) + 1 });
    }
    return matches;
  }

  function findSequences(pw, bpc) {
    const matches = [];
    const lower = pw.toLowerCase();
    let i = 0;
    while (i < lower.length - 2) {
      const d = lower.charCodeAt(i + 1) - lower.charCodeAt(i);
      if ((d === 1 || d === -1) && isAlnum(lower[i]) && isAlnum(lower[i + 1])) {
        let j = i + 1;
        while (j + 1 < lower.length && isAlnum(lower[j + 1]) &&
               lower.charCodeAt(j + 1) - lower.charCodeAt(j) === d) j++;
        const len = j - i + 1;
        if (len >= 3) {
          matches.push({ start: i, end: j + 1, type: 'sequence',
            label: d === 1 ? 'ascending sequence' : 'descending sequence',
            cost: bpc + Math.log2(len) + 1 });
          i = j + 1;
          continue;
        }
      }
      i++;
    }
    return matches;
  }

  function findKeyboardWalks(pw, bpc) {
    const matches = [];
    const lower = pw.toLowerCase();
    const rows = [];
    KEYBOARD_ROWS.forEach(function (r) { rows.push(r, r.split('').reverse().join('')); });
    let i = 0;
    while (i < lower.length - 2) {
      let best = 0;
      for (const row of rows) {
        let j = i + 1;
        while (j <= lower.length && row.includes(lower.slice(i, j))) j++;
        best = Math.max(best, j - 1 - i);
      }
      if (best >= 3) {
        matches.push({ start: i, end: i + best, type: 'keyboard',
          label: 'keyboard pattern', cost: bpc + Math.log2(best) + 2 });
        i += best;
      } else {
        i++;
      }
    }
    return matches;
  }

  function findWords(pw) {
    const matches = [];
    const lower = pw.toLowerCase();
    const variants = [lower].concat(LEET_VARIANTS.map(function (m) { return normalizeLeet(lower, m); }));
    variants.forEach(function (text) {
      COMMON_WORDS.forEach(function (word) {
        let idx = text.indexOf(word);
        while (idx !== -1) {
          matches.push({ start: idx, end: idx + word.length, type: 'word',
            label: 'common word', cost: 11 });
          idx = text.indexOf(word, idx + 1);
        }
      });
    });
    return matches;
  }

  function findYears(pw) {
    const matches = [];
    const re = /(19|20)\d{2}/g;
    let m;
    while ((m = re.exec(pw)) !== null) {
      matches.push({ start: m.index, end: m.index + 4, type: 'year', label: 'year', cost: 7 });
    }
    return matches;
  }

  // Keep the best (longest) non-overlapping matches.
  function resolveOverlaps(matches, length) {
    const sorted = matches.slice().sort(function (a, b) {
      return (b.end - b.start) - (a.end - a.start);
    });
    const taken = new Array(length).fill(false);
    const accepted = [];
    sorted.forEach(function (m) {
      for (let k = m.start; k < m.end; k++) if (taken[k]) return;
      for (let k = m.start; k < m.end; k++) taken[k] = true;
      accepted.push(m);
    });
    return { accepted: accepted, taken: taken };
  }

  /* ---------- Formatting ---------- */

  function formatDuration(seconds) {
    if (!isFinite(seconds)) return 'practically forever';
    if (seconds < 1) return 'instantly (under 1 second)';
    const units = [
      ['second', 60], ['minute', 60], ['hour', 24], ['day', 365], ['year', 1000]
    ];
    let value = seconds;
    for (let i = 0; i < units.length; i++) {
      if (value < units[i][1]) {
        const n = Math.floor(value);
        return n + ' ' + units[i][0] + (n === 1 ? '' : 's');
      }
      value = value / units[i][1];
    }
    // value is now in thousands of years
    const years = value * 1000;
    if (years < 1e6) return 'about ' + Math.round(years).toLocaleString('en-US') + ' years';
    if (years < 1e9) return 'about ' + Math.round(years / 1e6).toLocaleString('en-US') + ' million years';
    if (years < 1e12) return 'about ' + Math.round(years / 1e9).toLocaleString('en-US') + ' billion years';
    return 'trillions of years or more';
  }

  /* ---------- Main analysis ---------- */

  function emptyResult() {
    const checks = [
      { id: 'min8',     label: 'At least 8 characters',            pass: false, severity: 'required' },
      { id: 'rec12',    label: '12+ characters (recommended)',     pass: false, severity: 'recommended' },
      { id: 'upper',    label: 'Uppercase letters (A-Z)',          pass: false, severity: 'required' },
      { id: 'lower',    label: 'Lowercase letters (a-z)',          pass: false, severity: 'required' },
      { id: 'number',   label: 'Numbers (0-9)',                    pass: false, severity: 'required' },
      { id: 'special',  label: 'Special characters (!@#$...)',     pass: false, severity: 'required' },
      { id: 'common',   label: 'Not a commonly used password',     pass: false, severity: 'required' },
      { id: 'repeat',   label: 'No repeated characters or blocks', pass: false, severity: 'required' },
      { id: 'sequence', label: 'No predictable sequences',         pass: false, severity: 'required' }
    ];
    return {
      empty: true, length: 0, variety: 0, poolSize: 0, rawEntropy: 0, effectiveEntropy: 0,
      score: 0, level: LEVELS[0], checks: checks, findings: [], recommendations: [],
      explanation: [], crackTime: '-', patterns: [], isCommon: false
    };
  }

  function analyze(password) {
    const pw = typeof password === 'string' ? password : '';
    if (pw.length === 0) return emptyResult();

    const chars = Array.from(pw); // handles emoji / multi-byte characters
    const length = chars.length;
    const info = describeCharacters(pw);
    const pool = poolSize(info);
    const bpc = Math.log2(pool);
    const variety = ['lower', 'upper', 'digit', 'symbol'].filter(function (k) { return info[k]; }).length +
                    (info.other ? 1 : 0);
    const rawEntropy = length * bpc;

    /* Predictable patterns */
    const allMatches = [].concat(
      findRepeats(pw, bpc), findSequences(pw, bpc), findKeyboardWalks(pw, bpc),
      findWords(pw), findYears(pw)
    );
    const resolved = resolveOverlaps(allMatches, pw.length);
    let effective = 0;
    resolved.accepted.forEach(function (m) {
      effective += Math.min(m.cost, (m.end - m.start) * bpc);
    });
    for (let k = 0; k < pw.length; k++) if (!resolved.taken[k]) effective += bpc;
    effective = Math.max(0, Math.min(effective, rawEntropy));

    const patternTypes = {};
    resolved.accepted.forEach(function (m) { patternTypes[m.type] = (patternTypes[m.type] || 0) + 1; });
    const hasRepeat = !!patternTypes.repeat;
    const hasSequence = !!(patternTypes.sequence || patternTypes.keyboard);
    const common = isCommonPassword(pw);

    /* Score + caps */
    let score = Math.round(Math.min(100, (effective / MAX_SCORE_BITS) * 100));
    const caps = [];
    if (common) {
      if (score > 8) { score = 8; }
      caps.push('This matches a commonly used password, so attackers try it first. The score is capped at 8.');
    }
    if (length < 6) {
      if (score > 15) score = 15;
      caps.push('Passwords under 6 characters are capped as Very Weak.');
    } else if (length < 8) {
      if (score > 30) score = 30;
      caps.push('Passwords under 8 characters are capped as Weak.');
    } else if (length < 12 && score > 79) {
      score = 79;
      caps.push('Passwords under 12 characters cannot be rated Very Strong.');
    }
    // Single-type passwords are often plain words, which attackers guess far faster than
    // the random-character model assumes, so they cannot reach the top levels.
    if (variety < 2 && score > 59) {
      score = 59;
      caps.push('Passwords using only one character type are capped at Medium (they are often plain words).');
    } else if (variety < 3 && length < 20 && score > 79) {
      score = 79;
      caps.push('Passwords with fewer than 3 character types need 20+ characters to be rated Very Strong.');
    }
    const level = getLevel(score);

    /* Checklist */
    const checks = [
      { id: 'min8',     label: 'At least 8 characters',            pass: length >= 8,  severity: 'required' },
      { id: 'rec12',    label: '12+ characters (recommended)',     pass: length >= 12, severity: 'recommended' },
      { id: 'upper',    label: 'Uppercase letters (A-Z)',          pass: info.upper,   severity: 'required' },
      { id: 'lower',    label: 'Lowercase letters (a-z)',          pass: info.lower,   severity: 'required' },
      { id: 'number',   label: 'Numbers (0-9)',                    pass: info.digit,   severity: 'required' },
      { id: 'special',  label: 'Special characters (!@#$...)',     pass: info.symbol || info.other, severity: 'required' },
      { id: 'common',   label: 'Not a commonly used password',     pass: !common && !patternTypes.word, severity: 'required' },
      { id: 'repeat',   label: 'No repeated characters or blocks', pass: !hasRepeat,   severity: 'required' },
      { id: 'sequence', label: 'No predictable sequences',         pass: !hasSequence && !patternTypes.year, severity: 'required' }
    ];

    /* Findings: why did it get this score? */
    const findings = [];
    findings.push({ type: length >= 12 ? 'good' : (length >= 8 ? 'info' : 'bad'),
      text: 'Length is ' + length + ' character' + (length === 1 ? '' : 's') +
            '. Length is the biggest single factor in password strength.' });
    findings.push({ type: variety >= 3 ? 'good' : 'info',
      text: 'It uses ' + variety + ' of 4 character types, giving a pool of about ' + pool +
            ' possible characters (' + bpc.toFixed(1) + ' bits per character).' });
    if (common) findings.push({ type: 'bad', text: 'It matches (or is a small variation of) a very common password.' });
    if (patternTypes.word) findings.push({ type: 'bad', text: 'It contains a common word, even if disguised with substitutions like @ for a or 0 for o.' });
    if (patternTypes.keyboard) findings.push({ type: 'bad', text: 'It contains a keyboard pattern (such as qwerty or asdf), which attackers test early.' });
    if (patternTypes.sequence) findings.push({ type: 'bad', text: 'It contains a sequence such as abc or 123, which is easy to guess.' });
    if (patternTypes.repeat) findings.push({ type: 'bad', text: 'It contains repeated characters or repeated blocks, which add very little real strength.' });
    if (patternTypes.year) findings.push({ type: 'bad', text: 'It contains something that looks like a year (1900-2099). Years are among the first things attackers try.' });
    if (!resolved.accepted.length && !common) {
      findings.push({ type: 'good', text: 'No common words, sequences, keyboard patterns or repeats were detected.' });
    }

    const explanation = [];
    explanation.push('Raw entropy: ' + length + ' characters x ' + bpc.toFixed(2) + ' bits = ' + rawEntropy.toFixed(1) + ' bits.');
    if (rawEntropy - effective >= 0.5) {
      explanation.push('Predictable patterns reduce this to about ' + effective.toFixed(1) + ' bits of effective entropy (' +
        (rawEntropy - effective).toFixed(1) + ' bits lost).');
    } else {
      explanation.push('No predictable patterns were found, so effective entropy stays at about ' + effective.toFixed(1) + ' bits.');
    }
    explanation.push('Score = effective entropy / ' + MAX_SCORE_BITS + ' bits x 100 = ' + Math.round(Math.min(100, effective / MAX_SCORE_BITS * 100)) + '.');
    caps.forEach(function (c) { explanation.push(c); });
    explanation.push('Result: ' + score + '/100 (' + level.label + ').');

    /* Recommendations */
    const recs = [];
    if (length < 12) recs.push({ priority: 'high', text: 'Increase the length to at least 12-16 characters. Each extra character multiplies the work an attacker needs.' });
    if (common) recs.push({ priority: 'high', text: 'Avoid commonly used passwords. Choose something that is not on any popular password list.' });
    if (variety < 3) recs.push({ priority: 'medium', text: 'Mix different character types: uppercase, lowercase, numbers and symbols (or use a long passphrase of random words).' });
    if (hasSequence) recs.push({ priority: 'medium', text: 'Avoid predictable patterns like 123, abc or qwerty. Attackers try these first.' });
    if (hasRepeat) recs.push({ priority: 'medium', text: 'Avoid repeated characters such as aaa or abcabc.' });
    if (patternTypes.word || patternTypes.year) recs.push({ priority: 'medium', text: 'Avoid personal information and dictionary words (names, birthdays, years, pet names, favourite teams).' });
    recs.push({ priority: 'info', text: 'Use a unique password for every account. One leaked password should never unlock another account.' });
    recs.push({ priority: 'info', text: 'Consider using a reputable password manager so you can use long random passwords without memorising them.' });
    recs.push({ priority: 'info', text: 'Enable multi-factor authentication (MFA) wherever it is offered. It protects you even if a password leaks.' });

    // Estimated offline cracking time (average = half the search space).
    const seconds = Math.pow(2, Math.max(0, effective - 1)) / GUESSES_PER_SECOND;

    return {
      empty: false,
      length: length,
      variety: variety,
      poolSize: pool,
      rawEntropy: rawEntropy,
      effectiveEntropy: effective,
      score: score,
      level: level,
      checks: checks,
      findings: findings,
      recommendations: recs,
      explanation: explanation,
      crackTime: formatDuration(seconds),
      patterns: resolved.accepted.map(function (m) { return m.type; }),
      isCommon: common
    };
  }

  const api = { analyze: analyze, getLevel: getLevel, LEVELS: LEVELS, formatDuration: formatDuration };
  global.PasswordChecker = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
