/* Game Lobby — standalone Nostr game lobby (tic-tac-toe, connect 4, trivia).
 * Extracted from AgentWorld's proven game code; no 3D world, no rooms.
 * Protocol: kinds 30032/30033/30034, #room=gamelobby.
 * Plain script (no modules). Requires: nobleSecp (secp256k1.bundle.js). */
(function () {
'use strict';

/* ---------------- tiny utils ---------------- */
function $(id) { return document.getElementById(id); }
function hex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
function unhex(s) { var a = new Uint8Array(s.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16); return a; }
async function sha256hex(str) {
  var d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return hex(new Uint8Array(d));
}
function tag(ev, n) { for (var i = 0; i < ev.tags.length; i++) if (ev.tags[i][0] === n) return ev.tags[i][1]; return null; }

/* ---------------- identity ---------------- */
var S = nobleSecp;
var privHex = null, myPubHex = null, hasNsec = false;
var myName = 'guest';

/* bech32 (for npub -> hex) */
function bech32Decode(str) {
  var ALPH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var s = String(str).trim();
  var pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) return null;
  var hrp = s.slice(0, pos).toLowerCase(), data = [], i, j;
  for (i = pos + 1; i < s.length; i++) {
    var d = ALPH.indexOf(s[i].toLowerCase());
    if (d < 0) return null;
    data.push(d);
  }
  var vals = [];
  for (i = 0; i < hrp.length; i++) vals.push(hrp.charCodeAt(i) >> 5);
  vals.push(0);
  for (i = 0; i < hrp.length; i++) vals.push(hrp.charCodeAt(i) & 31);
  var chk = vals.concat(data);
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3], p = 1;
  for (i = 0; i < chk.length; i++) {
    var b = p >> 25;
    p = ((p & 0x1ffffff) << 5) ^ chk[i];
    for (j = 0; j < 5; j++) if ((b >> j) & 1) p ^= GEN[j];
  }
  if (p !== 1) return null;
  var payload = data.slice(0, -6), acc = 0, bits = 0, out = [];
  for (i = 0; i < payload.length; i++) {
    acc = (acc << 5) | payload[i]; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); }
  }
  return { hrp: hrp, bytes: out };
}
function npubToHex(s) {
  s = String(s).trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
  if (s.toLowerCase().indexOf('npub1') === 0) {
    var d = bech32Decode(s);
    if (d && d.hrp === 'npub' && d.bytes.length === 32)
      return d.bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  return null;
}
/* bech32 encode (to derive your npub from an nsec) */
function bech32Encode(hrp, bytes) {
  var ALPH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function step(p, v) {
    var b = p >> 25, j;
    p = ((p & 0x1ffffff) << 5) ^ v;
    for (j = 0; j < 5; j++) if ((b >> j) & 1) p ^= GEN[j];
    return p;
  }
  var data = [], acc = 0, bits = 0, i;
  for (i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31); }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31);
  var p = 1;
  for (i = 0; i < hrp.length; i++) p = step(p, hrp.charCodeAt(i) >> 5);
  p = step(p, 0);
  for (i = 0; i < hrp.length; i++) p = step(p, hrp.charCodeAt(i) & 31);
  for (i = 0; i < data.length; i++) p = step(p, data[i]);
  for (i = 0; i < 6; i++) p = step(p, 0);
  p ^= 1;
  var out = hrp + '1', j;
  for (j = 0; j < data.length; j++) out += ALPH[data[j]];
  for (j = 0; j < 6; j++) out += ALPH[(p >> (5 * (5 - j))) & 31];
  return out;
}
function nsecToHex(s) {
  var d = bech32Decode(s);
  if (d && d.hrp === 'nsec' && d.bytes.length === 32)
    return d.bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  return null;
}
function hexToNpub(h) {
  var bytes = [];
  for (var i = 0; i < 32; i++) bytes.push(parseInt(String(h).slice(i * 2, i * 2 + 2), 16));
  return bech32Encode('npub', bytes);
}


async function initIdentity() {
  var nsecHex = null;
  try { nsecHex = nsecToHex(localStorage.getItem('gl_nsec') || ''); } catch (e) {}
  if (nsecHex) {
    /* proven identity: this device signs everything AS your npub.
       The nsec itself never leaves this device — only signatures go out,
       and a signature can't be reversed into the key. */
    privHex = nsecHex; hasNsec = true;
  } else {
    try { privHex = localStorage.getItem('gl_privkey'); } catch (e) {}
    if (!privHex) {
      privHex = hex(S.utils.randomPrivateKey());
      try { localStorage.setItem('gl_privkey', privHex); } catch (e) {}
    }
    hasNsec = false;
  }
  myPubHex = hex(await S.schnorr.getPublicKey(unhex(privHex)));
}
async function makeEvent(kind, tags, content) {
  var created_at = Math.floor(Date.now() / 1000);
  var id = await sha256hex(JSON.stringify([0, myPubHex, created_at, kind, tags, content]));
  var sig = hex(await S.schnorr.sign(unhex(id), unhex(privHex)));
  return { id: id, pubkey: myPubHex, created_at: created_at, kind: kind, tags: tags, content: content, sig: sig };
}


/* ---------------- relays ---------------- */
var RELAYS = ['wss://nos.lol', 'wss://relay.snort.social', 'wss://relay.primal.net', 'wss://relay.damus.io'];
var sockets = [];
var roomId = 'gamelobby';
var subSeq = 0;
var activeSubs = [];
var connectedOnce = false;
function broadcast(msg) {
  for (var i = 0; i < sockets.length; i++) {
    var e = sockets[i];
    if (e.open) { try { e.ws.send(msg); } catch (_) {} }
  }
}
function publish(ev) { broadcast(JSON.stringify(['EVENT', ev])); }

function hook(entry) {
  entry.ws.onopen = function () {
    entry.open = true;
    if (!connectedOnce) { connectedOnce = true; sysLine('connected to relays'); }
    updateRelayDot();
    resub(entry);
  };
  entry.ws.onclose = function () { entry.open = false; updateRelayDot(); scheduleReconnect(entry, 4000); };
  entry.ws.onerror = function () { try { entry.ws.close(); } catch (e) {} };
  entry.ws.onmessage = function (ev) { handleMsg(ev.data); };
}
function scheduleReconnect(entry, delay) {
  setTimeout(function () {
    try { entry.ws = new WebSocket(entry.url); hook(entry); }
    catch (e) { scheduleReconnect(entry, 9000); }
  }, delay);
}
function connectRelays() {
  RELAYS.forEach(function (url) {
    var entry = { url: url, ws: null, open: false };
    try { entry.ws = new WebSocket(url); hook(entry); } catch (e) {}
    sockets.push(entry);
  });
}
function resub(entry) {
  activeSubs.forEach(function (s) {
    try { entry.ws.send(JSON.stringify(['REQ', s.id, s.filter])); } catch (e) {}
  });
}

function setSubs() {
  activeSubs.forEach(function (s) { broadcast(JSON.stringify(['CLOSE', s.id])); });
  subSeq++;
  var q = subSeq, r = roomId;
  activeSubs = [
    { id: 'gl:game:' + r + ':' + q, purpose: 'game', room: r,
      filter: { kinds: [30032, 30033, 30034], '#room': [r] } }
  ];
  activeSubs.forEach(function (s) { broadcast(JSON.stringify(['REQ', s.id, s.filter])); });
}

function handleMsg(data) {
  var m;
  try { m = JSON.parse(data); } catch (e) { return; }
  if (!m || m[0] !== 'EVENT') return;
  var ok = false;
  for (var i = 0; i < activeSubs.length; i++)
    if (activeSubs[i].id === m[1]) { ok = true; break; }
  if (!ok) return;
  var ev = m[2];
  if (ev.kind === 30032 || ev.kind === 30033 || ev.kind === 30034) onGameEvent(ev);
}

var GK = { SESSION: 30032, STATE: 30033, ANSWER: 30034 };
var GDEF = {
  tictactoe: { label: 'Tic-tac-toe', maxp: 2 },
  connect4:  { label: 'Connect 4', maxp: 2 },
  trivia:    { label: 'Trivia', maxp: 8 }
};
var games = {};        // gameId -> session
var gstates = {};      // gameId -> latest state
var ganswers = {};     // gameId -> {playerHex: choiceIdx}
var openGameId = null; // board currently displayed
var triviaTimers = {}; // gameId -> timeout id (host only)
var TRIVIA_ROUNDS = 5, TRIVIA_QSECS = 25, TRIVIA_RSECS = 6;

/* ---- pure game logic (unit-tested in node) ---- */
function tttWinner(b) {
  var L = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  for (var i = 0; i < L.length; i++) {
    var a = L[i][0], c = L[i][1], d = L[i][2];
    if (b[a] && b[a] === b[c] && b[a] === b[d]) return b[a];
  }
  for (var j = 0; j < 9; j++) if (!b[j]) return null;
  return 'draw';
}
function c4Drop(b, col, piece) {
  for (var r = 5; r >= 0; r--) {
    var i = r * 7 + col;
    if (!b[i]) { b[i] = piece; return r; }
  }
  return -1;
}
function c4Winner(b) {
  function at(r, c) { return (r < 0 || r > 5 || c < 0 || c > 6) ? null : b[r * 7 + c]; }
  for (var r = 0; r < 6; r++) for (var c = 0; c < 7; c++) {
    var p = at(r, c);
    if (!p) continue;
    if (at(r, c+1) === p && at(r, c+2) === p && at(r, c+3) === p) return p;
    if (at(r+1, c) === p && at(r+2, c) === p && at(r+3, c) === p) return p;
    if (at(r+1, c+1) === p && at(r+2, c+2) === p && at(r+3, c+3) === p) return p;
    if (at(r+1, c-1) === p && at(r+2, c-2) === p && at(r+3, c-3) === p) return p;
  }
  for (var k = 0; k < 42; k++) if (!b[k]) return null;
  return 'draw';
}

/* ---- trivia question bank (shared with the Mica bot) ---- */
var TRIVIA_BANK = [
  { q: 'Which planet is known as the Red Planet?', c: ['Venus', 'Mars', 'Jupiter', 'Mercury'], a: 1 },
  { q: 'How many legs does a spider have?', c: ['6', '8', '10', '4'], a: 1 },
  { q: 'What is the largest ocean on Earth?', c: ['Atlantic', 'Indian', 'Pacific', 'Arctic'], a: 2 },
  { q: 'What gas do plants absorb from the air?', c: ['Oxygen', 'Carbon dioxide', 'Nitrogen', 'Hydrogen'], a: 1 },
  { q: 'How many days are in a leap year?', c: ['365', '366', '367', '364'], a: 1 },
  { q: 'What is the capital of Japan?', c: ['Kyoto', 'Osaka', 'Tokyo', 'Beijing'], a: 2 },
  { q: 'H2O is the chemical formula for…', c: ['Salt', 'Sugar', 'Water', 'Oxygen'], a: 2 },
  { q: 'Which planet is famous for its rings?', c: ['Mars', 'Saturn', 'Venus', 'Neptune'], a: 1 },
  { q: 'How many colors are in a rainbow?', c: ['5', '6', '7', '8'], a: 2 },
  { q: 'What is the fastest land animal?', c: ['Lion', 'Greyhound', 'Cheetah', 'Horse'], a: 2 },
  { q: 'What do honeybees make?', c: ['Wax paper', 'Honey', 'Silk', 'Syrup'], a: 1 },
  { q: 'How many strings does a standard guitar have?', c: ['4', '5', '6', '7'], a: 2 },
  { q: 'What is the largest mammal on Earth?', c: ['Elephant', 'Blue whale', 'Giraffe', 'Hippo'], a: 1 },
  { q: 'Water boils at what temperature (°C)?', c: ['90', '95', '100', '110'], a: 2 },
  { q: 'Which of these is a prime number?', c: ['4', '6', '7', '9'], a: 2 },
  { q: 'What is the capital of France?', c: ['London', 'Paris', 'Rome', 'Madrid'], a: 1 },
  { q: 'How many sides does a hexagon have?', c: ['5', '6', '7', '8'], a: 1 },
  { q: 'Which planet is closest to the Sun?', c: ['Venus', 'Earth', 'Mercury', 'Mars'], a: 2 },
  { q: 'Which instrument has 88 keys?', c: ['Guitar', 'Piano', 'Violin', 'Drums'], a: 1 },
  { q: 'How many minutes are in an hour?', c: ['30', '60', '90', '100'], a: 1 },
  { q: 'What does a thermometer measure?', c: ['Weight', 'Temperature', 'Speed', 'Pressure'], a: 1 },
  { q: 'Which animal is a marsupial?', c: ['Kangaroo', 'Zebra', 'Panda', 'Koala'], a: 0 },
  { q: 'How many players does a soccer team field?', c: ['9', '10', '11', '12'], a: 2 },
  { q: 'What is frozen water called?', c: ['Steam', 'Ice', 'Mist', 'Dew'], a: 1 }
];

/* ---- protocol helpers ---- */
function nowSec() { return Math.floor(Date.now() / 1000); }
function newGameId() {
  var h = '0123456789abcdef', s = 'g';
  for (var i = 0; i < 8; i++) s += h[Math.floor(Math.random() * 16)];
  return s;
}
function dTag(ev) {
  var t = ev.tags || [];
  for (var i = 0; i < t.length; i++) if (t[i][0] === 'd') return t[i][1];
  return null;
}
async function pubGameSession(s) {
  s.at = nowSec();
  publish(await makeEvent(GK.SESSION, [['d', s.id], ['room', roomId]], JSON.stringify(s)));
}
async function pubGameState(st) {
  st.at = nowSec();
  publish(await makeEvent(GK.STATE, [['d', st.id], ['room', roomId]], JSON.stringify(st)));
}
async function pubAnswer(id, choice) {
  publish(await makeEvent(GK.ANSWER, [['d', id + ':' + myPubHex], ['room', roomId]],
    JSON.stringify({ v: 1, choice: choice })));
}
function gameName(s) {
  var n = (s.names && s.names[s.host]) || s.hostName || 'host';
  return GDEF[s.game].label + ' — ' + String(n).slice(0, 18);
}
function shortHex(h) { return '@' + String(h || '').slice(0, 8); }

/* ---- actions ---- */
async function startGame(game) {
  var id = newGameId();
  var s = { v: 1, id: id, game: game, status: 'open', host: myPubHex, hostName: myName,
            players: [myPubHex], names: {}, room: roomId, winner: null, at: nowSec() };
  s.names[myPubHex] = myName;
  games[id] = s;
  await pubGameSession(s);
  var st;
  if (game === 'tictactoe') {
    st = { v: 1, id: id, game: game, seq: 0, board: ['', '', '', '', '', '', '', '', ''],
           turn: myPubHex, winner: null, at: nowSec() };
  } else if (game === 'connect4') {
    var b = []; for (var i = 0; i < 42; i++) b.push('');
    st = { v: 1, id: id, game: game, seq: 0, board: b, turn: myPubHex, winner: null, at: nowSec() };
  } else {
    st = { v: 1, id: id, game: 'trivia', seq: 0, round: 0, phase: 'lobby',
           q: null, answers: {}, scores: {}, at: nowSec() };
  }
  gstates[id] = st;
  await pubGameState(st);
  renderGameList();
  openBoard(id);
  sysLine('you started ' + GDEF[game].label + ' — others can join from the lobby');
}
async function joinGame(id) {
  var s = games[id];
  if (!s || s.status !== 'open') return;
  if (s.players.indexOf(myPubHex) >= 0) { openBoard(id); return; }
  if (s.players.length >= GDEF[s.game].maxp) return;
  s.players.push(myPubHex);
  s.names[myPubHex] = myName;
  if (s.game !== 'trivia' && s.players.length >= 2) s.status = 'playing';
  games[id] = s;
  await pubGameSession(s);
  renderGameList();
  openBoard(id);
  sysLine('you joined ' + gameName(s));
}
async function finishGame(s, winner) {
  s.status = 'finished'; s.winner = winner || null;
  await pubGameSession(s);
  renderGameList(); renderBoard();
}
function otherPlayer(s) {
  for (var i = 0; i < s.players.length; i++)
    if (s.players[i] !== myPubHex) return s.players[i];
  return null;
}
async function tttMove(i) {
  var s = games[openGameId], st = gstates[openGameId];
  if (!s || !st || s.status !== 'playing' || st.winner) return;
  if (st.turn !== myPubHex || st.board[i]) return;
  var piece = (s.players[0] === myPubHex) ? 'X' : 'O';
  st.board[i] = piece;
  var w = tttWinner(st.board);
  st.winner = (w === 'draw') ? 'draw' : (w ? myPubHex : null);
  st.turn = otherPlayer(s);
  st.seq++;
  await pubGameState(st);
  renderBoard();
  if (st.winner) finishGame(s, st.winner);
}
async function c4Move(col) {
  var s = games[openGameId], st = gstates[openGameId];
  if (!s || !st || s.status !== 'playing' || st.winner) return;
  if (st.turn !== myPubHex) return;
  var piece = (s.players[0] === myPubHex) ? 'R' : 'Y';
  var board = st.board.slice();
  if (c4Drop(board, col, piece) < 0) return;   // column full
  st.board = board;
  var w = c4Winner(st.board);
  st.winner = (w === 'draw') ? 'draw' : (w ? myPubHex : null);
  st.turn = otherPlayer(s);
  st.seq++;
  await pubGameState(st);
  renderBoard();
  if (st.winner) finishGame(s, st.winner);
}
/* trivia: host drives rounds, everyone answers into their own 30034 slot */
async function triviaStart(id) {
  var s = games[id];
  if (!s || s.host !== myPubHex || s.status !== 'open') return;
  if (s.players.length < 2) { sysLine('trivia needs at least 2 players'); return; }
  s.status = 'playing';
  await pubGameSession(s);
  triviaAsk(id);
}
async function triviaAsk(id) {
  var s = games[id];
  if (!s || s.host !== myPubHex || s.status !== 'playing') return;
  var st = gstates[id] || { v: 1, id: id, game: 'trivia', seq: 0, scores: {} };
  var round = (st.round || 0) + 1;
  var q = TRIVIA_BANK[Math.floor(Math.random() * TRIVIA_BANK.length)];
  st.round = round; st.phase = 'question';
  st.q = { q: q.q, c: q.c, a: q.a };
  st.answers = {}; st.seq++;
  gstates[id] = st; ganswers[id] = {};
  await pubGameState(st);
  renderBoard();
  if (triviaTimers[id]) clearTimeout(triviaTimers[id]);
  triviaTimers[id] = setTimeout(function () { triviaReveal(id); }, TRIVIA_QSECS * 1000);
}
async function triviaReveal(id) {
  var s = games[id], st = gstates[id];
  if (!s || !st || s.host !== myPubHex || st.phase !== 'question') return;
  var ans = ganswers[id] || {};
  var scores = st.scores || {};
  for (var hx in ans) {
    if (ans[hx] === st.q.a) scores[hx] = (scores[hx] || 0) + 1;
    else if (!(hx in scores)) scores[hx] = 0;
  }
  for (var i = 0; i < s.players.length; i++)
    if (!(s.players[i] in scores)) scores[s.players[i]] = 0;
  st.answers = ans; st.scores = scores; st.phase = 'reveal'; st.seq++;
  await pubGameState(st);
  renderBoard();
  if (triviaTimers[id]) clearTimeout(triviaTimers[id]);
  triviaTimers[id] = setTimeout(function () {
    var cur = gstates[id];
    if (!cur || games[id].host !== myPubHex) return;
    if (cur.round >= TRIVIA_ROUNDS) {
      var best = null, bestN = -1, tie = false;
      for (var hx in cur.scores) {
        if (cur.scores[hx] > bestN) { best = hx; bestN = cur.scores[hx]; tie = false; }
        else if (cur.scores[hx] === bestN) tie = true;
      }
      finishGame(games[id], tie ? 'draw' : best);
    } else triviaAsk(id);
  }, TRIVIA_RSECS * 1000);
}
async function triviaAnswer(i) {
  var st = gstates[openGameId];
  if (!st || st.game !== 'trivia' || st.phase !== 'question') return;
  var cur = (ganswers[openGameId] || {})[myPubHex];
  if (cur === i) return;
  if (!ganswers[openGameId]) ganswers[openGameId] = {};
  ganswers[openGameId][myPubHex] = i;
  await pubAnswer(openGameId, i);
  renderBoard();
}

/* ---- event handlers ---- */
function onGameEvent(ev) {
  if (ev.kind === GK.SESSION) onGameSession(ev);
  else if (ev.kind === GK.STATE) onGameState(ev);
  else if (ev.kind === GK.ANSWER) onGameAnswer(ev);
}
function onGameSession(ev) {
  if (dTag(ev) === null) return;
  var s = null;
  try { s = JSON.parse(ev.content); } catch (e) { return; }
  if (!s || s.id !== dTag(ev) || !GDEF[s.game] || !Array.isArray(s.players)) return;
  if (!s.players.every(function (p) { return typeof p === 'string' && /^[0-9a-f]{64}$/.test(p); })) return;
  var old = games[s.id];
  if (old && (s.at || 0) < (old.at || 0)) return;   // older session update: ignore
  if (old && old.host !== s.host) return;          // host never changes
  games[s.id] = s;
  if (s.status === 'open' && s.players.indexOf(myPubHex) < 0 &&
      s.players.length < GDEF[s.game].maxp) {
    sysLine(gameName(s) + ' is open — tap 🎮 to join');
  }
  renderGameList();
  if (openGameId === s.id) renderBoard();
}
function onGameState(ev) {
  var st = null;
  try { st = JSON.parse(ev.content); } catch (e) { return; }
  if (!st || st.id !== dTag(ev) || !GDEF[st.game]) return;
  if (!Array.isArray(st.board) || st.board.length !== (st.game === 'connect4' ? 42 : 9)) {
    if (st.game !== 'trivia') return;
  }
  var old = gstates[st.id];
  if (old && (st.seq || 0) <= (old.seq || 0)) return;   // stale move: ignore
  gstates[st.id] = st;
  if (openGameId === st.id) renderBoard();
}
function onGameAnswer(ev) {
  var d = dTag(ev);
  if (!d) return;
  var parts = d.split(':');
  if (parts.length !== 2) return;
  var id = parts[0], hx = parts[1];
  if (hx !== ev.pubkey) return;   // answer slot belongs to its author
  var a = null;
  try { a = JSON.parse(ev.content); } catch (e) { return; }
  if (!a || typeof a.choice !== 'number' || a.choice < 0 || a.choice > 3) return;
  if (!ganswers[id]) ganswers[id] = {};
  ganswers[id][hx] = a.choice;
  if (openGameId === id) renderBoard();
}

/* ---- lobby + board UI ---- */
function openGames() {
  closeBoard();
  renderGameList();
}
function closeGames() {}
function renderGameList() {
  var list = $('gamelist');
  var ids = Object.keys(games).filter(function (id) { return games[id].status !== 'finished'; });
  ids.sort(function (a, b) { return (games[b].at || 0) - (games[a].at || 0); });
  var done = Object.keys(games).filter(function (id) { return games[id].status === 'finished'; });
  done.sort(function (a, b) { return (games[b].at || 0) - (games[a].at || 0); });
  done = done.slice(0, 3);
  var html = '';
  function row(s) {
    var me = s.players.indexOf(myPubHex) >= 0;
    var btn;
    if (s.status === 'open' && !me && s.players.length < GDEF[s.game].maxp)
      btn = '<button data-join="' + s.id + '">Join</button>';
    else if (me || s.status !== 'open')
      btn = '<button data-open="' + s.id + '">Open</button>';
    else btn = '<span class="gs">full</span>';
    var pl = s.players.map(function (p) { return (s.names && s.names[p]) || shortHex(p); }).join(', ');
    var res = '';
    if (s.status === 'finished') {
      res = ' · ' + (s.winner === 'draw' ? 'draw' :
        'winner: ' + (((s.names && s.names[s.winner]) || shortHex(s.winner)) || '?'));
    }
    return '<div class="gamerow"><div class="gt">' + escHtml(GDEF[s.game].label) + '</div>' +
      '<div class="gs">' + escHtml(gameName(s)) + ' · ' + s.status + ' · ' +
      s.players.length + '/' + GDEF[s.game].maxp + res + '<br>' + escHtml(pl) + '</div>' + btn + '</div>';
  }
  ids.forEach(function (id) { html += row(games[id]); });
  done.forEach(function (id) { html += row(games[id]); });
  if (!html) html = '<div class="gs">No games yet — start one below.</div>';
  list.innerHTML = html;
  var btns = list.querySelectorAll('button[data-join]');
  for (var i = 0; i < btns.length; i++)
    btns[i].addEventListener('click', function () { joinGame(this.getAttribute('data-join')); });
  var ops = list.querySelectorAll('button[data-open]');
  for (var j = 0; j < ops.length; j++)
    ops[j].addEventListener('click', function () { openBoard(this.getAttribute('data-open')); });
  var anyOpen = ids.some(function (id) {
    var s = games[id];
    return s.status === 'open' && s.players.indexOf(myPubHex) < 0;
  });
  var dot = $('gamebtn').querySelector('.dot');
  if (dot) dot.style.display = anyOpen && $('boardpanel').classList.contains('open') ? '' : 'none';
  var ls = $('lobbystatus');
  if (ls) {
    var n = ids.filter(function (id) { return games[id].status === 'open'; }).length;
    ls.textContent = n ? n + ' open game' + (n > 1 ? 's' : '') + ' — tap Join to play' : 'no open games right now';
  }
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function openBoard(id) {
  if (!games[id]) return;
  openGameId = id;
  closeGames();
  $('boardpanel').classList.add('open');
  renderBoard();
}
function closeBoard() {
  openGameId = null;
  $('boardpanel').classList.remove('open');
}
function pname(s, hx) {
  return escHtml((s.names && s.names[hx]) || shortHex(hx));
}
function renderBoard() {
  var body = $('boardbody'), status = $('boardstatus'), title = $('boardtitle');
  var s = games[openGameId], st = gstates[openGameId];
  if (!s) { closeBoard(); return; }
  title.textContent = '🎮 ' + GDEF[s.game].label;
  var html = '', stat = '';
  if (s.game === 'tictactoe') {
    var r = renderTTT(s, st); stat = r.stat; html = r.html;
  } else if (s.game === 'connect4') {
    var r2 = renderC4(s, st); stat = r2.stat; html = r2.html;
  } else {
    var r3 = renderTrivia(s, st); stat = r3.stat; html = r3.html;
  }
  status.innerHTML = stat;
  body.innerHTML = html;
  bindBoardButtons(s, st);
}
function turnText(s, st) {
  if (!st || st.winner) {
    if (!st || !st.winner) return 'waiting for players…';
    if (st.winner === 'draw') return "it's a draw!";
    return (st.winner === myPubHex ? 'you win! 🎉' : pname(s, st.winner) + ' wins!');
  }
  if (s.status !== 'playing') return 'waiting for players…';
  return st.turn === myPubHex ? 'your move' : pname(s, st.turn) + "'s move";
}
function renderTTT(s, st) {
  var html = '<div id="tttgrid">';
  var b = (st && st.board) || ['', '', '', '', '', '', '', '', ''];
  for (var i = 0; i < 9; i++)
    html += '<button class="cell" data-ttt="' + i + '">' + (b[i] || '') + '</button>';
  html += '</div>';
  return { stat: escHtml(turnText(s, st)), html: html };
}
function renderC4(s, st) {
  var b = (st && st.board) || [];
  while (b.length < 42) b.push('');
  var html = '<div id="c4grid">';
  for (var c = 0; c < 7; c++)
    html += '<button class="cell top" data-c4="' + c + '">▼</button>';
  for (var r = 0; r < 6; r++) for (var cc = 0; cc < 7; cc++) {
    var v = b[r * 7 + cc];
    html += '<button class="cell" data-c4="' + cc + '">' + (v === 'R' ? '🔴' : v === 'Y' ? '🟡' : '') + '</button>';
  }
  html += '</div>';
  return { stat: escHtml(turnText(s, st)), html: html };
}
function renderTrivia(s, st) {
  var html = '', stat = '';
  var me = myPubHex;
  if (s.status === 'open') {
    stat = escHtml(s.players.length + ' player' + (s.players.length > 1 ? 's' : '') + ' — waiting');
    html = '<div class="gs">' + s.players.map(function (p) { return pname(s, p); }).join(', ') + '</div>';
    if (s.host === me)
      html += '<div style="text-align:center;margin-top:10px"><button class="gstartbtn" data-trivstart="1">Start rounds</button></div>';
    else html += '<div class="gs" style="text-align:center">host starts the rounds…</div>';
    return { stat: stat, html: html };
  }
  if (!st || st.phase === 'lobby') return { stat: 'starting…', html: '' };
  stat = 'round ' + st.round + '/' + TRIVIA_ROUNDS;
  if (st.phase === 'question' && st.q) {
    html = '<div class="trivq">' + escHtml(st.q.q) + '</div>';
    var mine = (ganswers[s.id] || {})[me];
    for (var i = 0; i < st.q.c.length; i++)
      html += '<button class="trivchoice' + (mine === i ? ' picked' : '') + '" data-tqa="' + i + '">' +
        escHtml(st.q.c[i]) + '</button>';
    var n = Object.keys(ganswers[s.id] || {}).length;
    html += '<div class="gs" style="text-align:center">' + n + '/' + s.players.length + ' answered</div>';
  } else if (st.phase === 'reveal' && st.q) {
    html = '<div class="trivq">' + escHtml(st.q.q) + '</div>';
    var mine2 = (ganswers[s.id] || {})[me];
    for (var j = 0; j < st.q.c.length; j++) {
      var cls = 'trivchoice';
      if (j === st.q.a) cls += ' right';
      else if (mine2 === j) cls += ' wrong';
      html += '<button class="' + cls + '" disabled>' + escHtml(st.q.c[j]) + '</button>';
    }
    html += '<div class="trivscores">' + Object.keys(st.scores || {}).sort(function (a, b) {
      return (st.scores[b] || 0) - (st.scores[a] || 0);
    }).map(function (p) {
      return '<div>' + pname(s, p) + ': ' + (st.scores[p] || 0) + '</div>';
    }).join('') + '</div>';
  }
  if (s.status === 'finished') {
    stat = s.winner === 'draw' ? "it's a draw!" :
      (s.winner === me ? 'you win! 🎉' : pname(s, s.winner) + ' wins! 🎉');
  }
  return { stat: stat, html: html };
}
function bindBoardButtons(s, st) {
  var body = $('boardbody');
  var tcells = body.querySelectorAll('button[data-ttt]');
  for (var i = 0; i < tcells.length; i++)
    tcells[i].addEventListener('click', function () { tttMove(+this.getAttribute('data-ttt')); });
  var ccells = body.querySelectorAll('button[data-c4]');
  for (var j = 0; j < ccells.length; j++)
    ccells[j].addEventListener('click', function () { c4Move(+this.getAttribute('data-c4')); });
  var qa = body.querySelectorAll('button[data-tqa]');
  for (var k = 0; k < qa.length; k++)
    qa[k].addEventListener('click', function () { triviaAnswer(+this.getAttribute('data-tqa')); });
  var ts = body.querySelectorAll('button[data-trivstart]');
  for (var m = 0; m < ts.length; m++)
    ts[m].addEventListener('click', function () { triviaStart(openGameId); });
  var sb = body.querySelectorAll('button.gstartbtn');
  for (var n = 0; n < sb.length; n++)
    sb[n].style.cssText = 'background:#3b5bd6;border:none;color:#fff;border-radius:8px;padding:8px 18px;font-size:14px;';
}
function bindGames() {
  $('gamebtn').innerHTML = '🎮<span class="dot" style="display:none">●</span>';
  $('gamebtn').addEventListener('click', function () { openGames(); });
  $('bclose').addEventListener('click', closeBoard);
  $('gstart-ttt').addEventListener('click', function () { startGame('tictactoe'); });
  $('gstart-c4').addEventListener('click', function () { startGame('connect4'); });
  $('gstart-trivia').addEventListener('click', function () { startGame('trivia'); });
}
function clearGames() {
  games = {}; gstates = {}; ganswers = {}; openGameId = null;
  for (var id in triviaTimers) clearTimeout(triviaTimers[id]);
  triviaTimers = {};
  closeGames(); closeBoard();
}

/* ---------------- input: joystick / look / tap / keys ---------------- */

/* ---------------- status line + settings ---------------- */
function updateRelayDot() {
  var n = sockets.filter(function (s) { return s.open; }).length;
  var el = $('relaydot');
  if (el) el.textContent = n + '/' + sockets.length + ' relays';
}
function sysLine(t) {
  var el = $('statusline');
  if (!el) return;
  var div = document.createElement('div');
  div.textContent = t;
  el.insertBefore(div, el.firstChild);
  while (el.children.length > 3) el.removeChild(el.lastChild);
}
function openSettings() {
  $('glname').value = (myName === 'guest') ? '' : myName;
  $('nsecin').value = '';
  $('nsecin').placeholder = hasNsec ? 'nsec saved on this device — enter a new one to replace it' : 'nsec1… (stays on this device)';
  $('loginmsg').textContent = '';
  $('settingspanel').classList.add('open');
}
function closeSettings() { $('settingspanel').classList.remove('open'); }
async function saveLogin() {
  var msg = '';
  var nsecInput = $('nsecin').value.trim();
  if (nsecInput) {
    var nh = nsecToHex(nsecInput);
    if (!nh) { $('loginmsg').textContent = 'that nsec doesn\u2019t decode \u2014 nothing saved'; return; }
    try { localStorage.setItem('gl_nsec', nsecInput); } catch (e) {}
    await initIdentity();
    $('nsecin').value = '';
    msg = 'proven identity \u2014 you sign as ' + shortHex(myPubHex) + '. ';
  }
  var nm = $('glname').value.trim().slice(0, 24);
  myName = nm || (hasNsec ? shortHex(myPubHex) : 'guest');
  try { localStorage.setItem('gl_name', myName); } catch (e) {}
  $('loginmsg').textContent = msg + 'playing as ' + myName;
  renderGameList();
  if (openGameId) renderBoard();
}
function bindSettings() {
  $('setbtn').addEventListener('click', function () {
    $('settingspanel').classList.contains('open') ? closeSettings() : openSettings();
  });
  $('setclose').addEventListener('click', closeSettings);
  $('pairsave').addEventListener('click', saveLogin);
  $('nsecclear').addEventListener('click', async function () {
    try { localStorage.removeItem('gl_nsec'); } catch (e) {}
    $('nsecin').value = '';
    await initIdentity();
    openSettings();
    $('loginmsg').textContent = 'nsec forgotten on this device';
  });
}

/* ---------------- init ---------------- */
async function init() {
  try { myName = localStorage.getItem('gl_name') || 'guest'; } catch (e) {}
  bindSettings();
  bindGames();
  try { await initIdentity(); }
  catch (e) { sysLine('identity error: ' + e.message); return; }
  if (myName === 'guest' && hasNsec) myName = shortHex(myPubHex);
  setSubs();
  connectRelays();
  sysLine('welcome to the game lobby \u2014 start a game or join one \U0001F3AE');
  renderGameList();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

/* Headless QA hook — only exposed with ?awtest=1 in the URL. */
try {
  if (new URLSearchParams(location.search).get('awtest') === '1') {
    window.AWTEST = {
      games: function () { return games; },
      gstates: function () { return gstates; },
      myPub: function () { return myPubHex; },
      onGameSession: onGameSession,
      onGameState: onGameState,
      renderGameList: renderGameList
    };
  }
} catch (e) {}

})();
