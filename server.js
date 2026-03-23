'use strict';

const express    = require('express');
const crypto     = require('crypto');
const path       = require('path');
const { encode, decode } = require('./VoxCipher');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const HTTP_PORT = process.env.PORT || 3000;

function getHost(req) {
    return req?.get('host') || 'localhost:' + HTTP_PORT;
}

// ── In-memory state ───────────────────────────────────────────────────────────
const rooms   = new Map();
const tokens  = new Map();
const signalQueues = new Map(); // "roomId:userId" → [{from, type, payload, ts}]

class Room {
    constructor(id, password, label) {
        this.id           = id;
        this.password     = password;
        this.label        = label || id;
        this.members      = new Map();
        this.createdAt    = Date.now();
        this.lastActivity = Date.now();
    }
}

class Member {
    constructor(userId, userName) {
        this.userId     = userId;
        this.userName   = userName;
        this.isMuted    = false;
        this.isSpeaking = false;
        this.lastSeen   = Date.now();
    }
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
const rateLimits = new Map();
function rateLimit(req, res, maxPerMinute) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    let entry = rateLimits.get(ip);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + 60000 };
        rateLimits.set(ip, entry);
    }
    entry.count++;
    if (entry.count > maxPerMinute) {
        res.status(429).json({ error: 'Too many requests' });
        return false;
    }
    return true;
}

app.post('/join', (req, res, next) => { if (rateLimit(req, res, 30)) next(); });
app.post('/api/rooms', (req, res, next) => { if (rateLimit(req, res, 20)) next(); });

// ── Dashboard API ─────────────────────────────────────────────────────────────

app.get('/api/rooms', (req, res) => {
    const host = getHost(req);
    const proto = req.secure || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
    const list = Array.from(rooms.values()).map(r => ({
        id:          r.id,
        label:       r.label,
        password:    r.password,
        memberCount: r.members.size,
        createdAt:   r.createdAt,
        hash:        encode(host, r.id, r.password),
        joinUrl:     `${proto}://${host}/join?r=${encodeURIComponent(r.id)}&p=${encodeURIComponent(r.password)}`,
    }));
    res.json({ rooms: list, host });
});

app.post('/api/rooms', (req, res) => {
    const { label, password } = req.body;
    const host = getHost(req);
    const id   = genId();
    const pwd  = password || genPass();
    rooms.set(id, new Room(id, pwd, label || ('Room ' + id)));

    const hash = encode(host, id, pwd);
    const proto = req.secure || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
    console.log(`[Room] Created ${id}  hash: ${hash}`);

    res.json({
        success: true,
        id, label: rooms.get(id).label, password: pwd,
        hash,
        joinUrl: `${proto}://${host}/join?r=${id}&p=${encodeURIComponent(pwd)}`,
    });
});

app.delete('/api/rooms/:id', (req, res) => {
    const id = req.params.id.toUpperCase();
    if (rooms.has(id)) {
        rooms.delete(id);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

// ── App Signaling ─────────────────────────────────────────────────────────────

app.post('/join', (req, res) => {
    const { room_id, password, user_id, user_name } = req.body;
    if (!room_id || !user_id || !user_name)
        return res.status(400).json({ success: false, error: 'Missing fields' });

    const rid  = room_id.toUpperCase();
    let room   = rooms.get(rid);

    if (!room) {
        room = new Room(rid, password || '', rid);
        rooms.set(rid, room);
    } else if (room.password && room.password !== password) {
        return res.status(403).json({ success: false, error: 'Wrong password' });
    }

    // Clean previous session for this user (reconnect case)
    tokens.forEach((data, t) => {
        if (data.roomId === rid && data.userId === user_id) tokens.delete(t);
    });
    signalQueues.delete(`${rid}:${user_id}`);

    const token = crypto.randomBytes(16).toString('hex');
    tokens.set(token, { roomId: rid, userId: user_id });
    room.members.set(user_id, new Member(user_id, user_name));
    room.lastActivity = Date.now();

    console.log(`[Join] ${user_name} → ${rid} (${room.members.size} online)`);

    res.json({
        success:      true,
        token,
        room_id:      rid,
        member_count: room.members.size,
        members:      memberList(room),
    });
});

app.post('/leave', (req, res) => {
    const { room_id, user_id, token } = req.body;
    if (!room_id) return res.status(400).json({ error: 'Missing room_id' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });
    const room = rooms.get(rid);
    if (room) { room.members.delete(user_id); if (!room.members.size) rooms.delete(rid); }
    tokens.delete(token);
    signalQueues.delete(`${rid}:${user_id}`);
    console.log(`[Leave] ${user_id} left ${rid}`);
    res.json({ success: true });
});

app.get('/poll', (req, res) => {
    const { room_id, user_id, token } = req.query;
    if (!room_id) return res.status(400).json({ error: 'Missing room_id' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });
    const room = rooms.get(rid);
    if (!room) return res.json({ disbanded: true });
    const m = room.members.get(user_id);
    if (m) { m.lastSeen = Date.now(); room.lastActivity = Date.now(); }
    res.json({ members: memberList(room), member_count: room.members.size });
});

app.post('/ping', (req, res) => {
    const { room_id, user_id, token, muted } = req.body;
    if (!room_id) return res.status(400).json({ error: 'Missing room_id' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });
    const room = rooms.get(rid);
    if (room) {
        const m = room.members.get(user_id);
        if (m) {
            m.lastSeen = Date.now();
            if (typeof muted === 'boolean') m.isMuted = muted;
            room.lastActivity = Date.now();
        }
    }
    res.json({ ok: true });
});

// ── WebRTC Signaling ──────────────────────────────────────────────────────────

app.post('/signal', (req, res) => {
    const { room_id, user_id, token, target_id, type, payload } = req.body;
    if (!room_id || !user_id || !target_id || !type || !payload)
        return res.status(400).json({ error: 'Missing fields' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });

    const key = `${rid}:${target_id}`;
    if (!signalQueues.has(key)) signalQueues.set(key, []);
    signalQueues.get(key).push({ from: user_id, type, payload, ts: Date.now() });
    res.json({ ok: true });
});

app.get('/signal', (req, res) => {
    const { room_id, user_id, token } = req.query;
    if (!room_id || !user_id) return res.status(400).json({ error: 'Missing fields' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });

    const key = `${rid}:${user_id}`;
    const signals = signalQueues.get(key) || [];
    signalQueues.set(key, []);
    res.json({ signals });
});

// Browser join redirect
app.get('/join', (req, res) => {
    const { r, p } = req.query;
    if (!r) return res.status(400).send('Missing room');
    const host     = getHost(req);
    const hash     = encode(host, r, p || '');
    const safeR    = encodeURIComponent(r);
    const safeP    = encodeURIComponent(p || '');
    const safeHost = encodeURIComponent(host);
    const deepLink = `voxlink://join?s=${safeHost}&r=${safeR}&p=${safeP}`;
    res.send(`<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join ${escHtml(r)} · VoxLink</title>
<style>*{box-sizing:border-box;margin:0;padding:0}
body{background:#111;color:#fff;font-family:system-ui,sans-serif;display:flex;
align-items:center;justify-content:center;min-height:100vh;padding:24px}
.c{background:#1a1a1a;border-radius:16px;padding:36px 28px;max-width:340px;width:100%;text-align:center}
h1{font-size:20px;color:#888;font-weight:400;margin-bottom:20px}
.room{font-size:36px;font-weight:800;color:#4ade80;letter-spacing:4px;margin-bottom:6px}
.pwd{color:#666;font-size:13px;margin-bottom:20px}.pwd strong{color:#ccc}
.hash-box{background:#111;border:1px solid #222;border-radius:8px;padding:12px;
margin-bottom:24px;font-family:monospace;font-size:11px;color:#4ade80;
word-break:break-all;text-align:left}
.hash-label{color:#555;font-size:11px;margin-bottom:6px}
.btn{display:block;padding:14px;background:#4ade80;color:#111;font-size:15px;
font-weight:700;border-radius:10px;text-decoration:none;margin-bottom:10px}
.note{color:#444;font-size:11px;margin-top:20px;line-height:1.6}</style>
</head><body><div class="c">
<div style="font-size:40px;margin-bottom:12px">🎮</div>
<h1>You're invited to join</h1>
<div class="room">${escHtml(r)}</div>
${p ? `<div class="pwd">Password: <strong>${escHtml(p)}</strong></div>` : '<div class="pwd">No password</div>'}
<div class="hash-label">Paste this hash into VoxLink app:</div>
<div class="hash-box" id="hashEl">${escHtml(hash)}</div>
<a class="btn" href="${escHtml(deepLink)}">Open in VoxLink App &rarr;</a>
<div class="note">Copy the hash above and paste it into the app if the button doesn't work.</div>
</div>
<script>setTimeout(function(){window.location.href=${JSON.stringify(deepLink)}},500)</script>
</body></html>`);
});

// ── Cleanup ───────────────────────────────────────────────────────────────────
const MEMBER_TIMEOUT  = 90000;
const ROOM_TIMEOUT    = 600000;

setInterval(()=>{
    const now = Date.now();
    const activeUsers = new Set();
    let removed = 0;
    rooms.forEach((r,rid)=>{
        r.members.forEach((m,uid)=>{
            if(now-m.lastSeen > MEMBER_TIMEOUT) {
                r.members.delete(uid);
                signalQueues.delete(`${rid}:${uid}`);
                removed++;
            } else {
                activeUsers.add(`${rid}:${uid}`);
            }
        });
        if (!r.members.size && now-r.lastActivity > ROOM_TIMEOUT) {
            rooms.delete(rid);
        }
    });
    if (removed) console.log(`[Cleanup] Removed ${removed} stale members`);
    tokens.forEach((data, t) => {
        if (!activeUsers.has(`${data.roomId}:${data.userId}`)) tokens.delete(t);
    });
    // Clean stale signal queue entries (older than 30s)
    signalQueues.forEach((queue, key) => {
        const filtered = queue.filter(s => now - s.ts < 30000);
        if (filtered.length === 0) signalQueues.delete(key);
        else signalQueues.set(key, filtered);
    });
    rateLimits.forEach((v,k)=>{ if(now>v.resetAt) rateLimits.delete(k); });
}, 30000);

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function checkToken(t,r,u){ const d=tokens.get(t); return d&&d.roomId===r&&d.userId===u; }
function memberList(room){ return Array.from(room.members.values()).map(m=>({user_id:m.userId,user_name:m.userName,muted:m.isMuted,speaking:m.isSpeaking})); }
function genId(){ const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return Array.from({length:6},()=>c[Math.floor(Math.random()*c.length)]).join(''); }
function genPass(){ const c='abcdefghjkmnpqrstuvwxyz23456789'; return Array.from({length:4},()=>c[Math.floor(Math.random()*c.length)]).join(''); }

app.listen(HTTP_PORT, ()=>{
    console.log(`\n🎮 VoxLink Server`);
    console.log(`Dashboard → http://localhost:${HTTP_PORT}/`);
});
