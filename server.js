'use strict';

const express    = require('express');
const dgram      = require('dgram');
const crypto     = require('crypto');
const path       = require('path');
const { encode, decode } = require('./VoxCipher');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const HTTP_PORT = process.env.PORT || 3000;
const UDP_PORT  = process.env.UDP_PORT || 45000;

// Auto-detect own hostname from request headers
function getHost(req) {
    return req?.get('host') || 'localhost:' + HTTP_PORT;
}

// ── In-memory state ───────────────────────────────────────────────────────────
const rooms   = new Map();
const tokens  = new Map();
const udpKeys = new Map(); // "ROOMID:userId" → 4-byte Buffer

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

// ── Dashboard API ─────────────────────────────────────────────────────────────

// List rooms + their hashes
app.get('/api/rooms', (req, res) => {
    const host = getHost(req);
    const list = Array.from(rooms.values()).map(r => ({
        id:          r.id,
        label:       r.label,
        password:    r.password,
        memberCount: r.members.size,
        createdAt:   r.createdAt,
        hash:        encode(host, r.id, r.password),
        joinUrl:     `http://${host}/join?r=${encodeURIComponent(r.id)}&p=${encodeURIComponent(r.password)}`,
    }));
    res.json({ rooms: list, host });
});

// Create room → return hash
app.post('/api/rooms', (req, res) => {
    const { label, password } = req.body;
    const host = getHost(req);
    const id   = genId();
    const pwd  = password || genPass();
    rooms.set(id, new Room(id, pwd, label || ('Room ' + id)));

    const hash = encode(host, id, pwd);
    console.log(`[Room] Created ${id}  hash: ${hash}`);

    res.json({
        success: true,
        id, label: rooms.get(id).label, password: pwd,
        hash,
        joinUrl: `http://${host}/join?r=${id}&p=${encodeURIComponent(pwd)}`,
    });
});

// Delete room
app.delete('/api/rooms/:id', (req, res) => {
    const id = req.params.id.toUpperCase();
    rooms.has(id) ? rooms.delete(id) && res.json({ success: true })
                  : res.status(404).json({ error: 'Not found' });
});

// ── App Signaling ─────────────────────────────────────────────────────────────

app.post('/join', (req, res) => {
    const { room_id, password, user_id, user_name } = req.body;
    if (!room_id || !user_id || !user_name)
        return res.status(400).json({ success: false, error: 'Missing fields' });

    const rid  = room_id.toUpperCase();
    let room   = rooms.get(rid);

    if (!room) {
        // App-created room (host made it in-app)
        room = new Room(rid, password || '', rid);
        rooms.set(rid, room);
    } else if (room.password && room.password !== password) {
        return res.status(403).json({ success: false, error: 'Wrong password' });
    }

    const token = crypto.randomBytes(16).toString('hex');
    // 4-byte UDP auth key derived from token — sent in UDP header for validation
    const udpKey = crypto.createHash('md5').update(token + rid).digest().slice(0, 4);
    tokens.set(token, { roomId: rid, userId: user_id });
    room.members.set(user_id, new Member(user_id, user_name));
    room.lastActivity = Date.now();

    // Store UDP key for validation
    udpKeys.set(`${rid}:${user_id}`, udpKey);

    console.log(`[Join] ${user_name} → ${rid} (${room.members.size} online)`);

    res.json({
        success:      true,
        token,
        udp_key:      udpKey.toString('hex'),
        room_id:      rid,
        member_count: room.members.size,
        members:      memberList(room),
        udp_host:     getHost(req).split(':')[0],
        udp_port:     parseInt(UDP_PORT),
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
    udpKeys.delete(`${rid}:${user_id}`);
    res.json({ success: true });
});

app.get('/poll', (req, res) => {
    const { room_id, user_id, token } = req.query;
    if (!room_id) return res.status(400).json({ error: 'Missing room_id' });
    const rid = room_id.toUpperCase();
    if (!checkToken(token, rid, user_id)) return res.status(401).json({ error: 'Bad token' });
    const room = rooms.get(rid);
    if (!room) return res.json({ disbanded: true });
    const m = room.members.get(user_id); if (m) m.lastSeen = Date.now();
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

// Browser join redirect (for share links)
app.get('/join', (req, res) => {
    const { r, p } = req.query;
    if (!r) return res.status(400).send('Missing room');
    const host     = getHost(req);
    const hash     = encode(host, r, p || '');
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
<div class="hash-box" id="hashEl">${hash}</div>
<a class="btn" href="voxlink://join?s=${encodeURIComponent(host)}&r=${r}&p=${encodeURIComponent(p||'')}">Open in VoxLink App →</a>
<div class="note">Copy the hash above and paste it into the app if the button doesn't work.</div>
</div>
<script>setTimeout(()=>{window.location.href='voxlink://join?s=${encodeURIComponent(host)}&r=${r}&p=${encodeURIComponent(p||'')}'},500)</script>
</body></html>`);
});

// ── UDP Relay ─────────────────────────────────────────────────────────────────
const udp = dgram.createSocket('udp4');
const udpMap = new Map();

udp.on('message', (msg, rinfo) => {
    if (msg.length < 24) return; // 8 room + 8 user + 4 udpKey + 4 seq = 24 header
    const roomId = msg.slice(0,8).toString('utf8').replace(/\0/g,'').trim();
    const userId = msg.slice(8,16).toString('utf8').replace(/\0/g,'').trim();
    if (!roomId||!userId) return;

    // Validate UDP auth key
    const pktKey = msg.slice(16, 20);
    const expected = udpKeys.get(`${roomId}:${userId}`);
    if (!expected || !pktKey.equals(expected)) return; // drop unauthenticated packets

    udpMap.set(`${roomId}:${userId}`, { addr: rinfo.address, port: rinfo.port, t: Date.now() });
    const room = rooms.get(roomId); if (!room) return;
    room.members.forEach((_,mid)=>{
        if (mid===userId) return;
        const d = udpMap.get(`${roomId}:${mid}`);
        if (d && Date.now()-d.t < 30000) udp.send(msg, d.port, d.addr);
    });
});
udp.bind(UDP_PORT, ()=>console.log(`UDP → :${UDP_PORT}`));

// ── Cleanup ───────────────────────────────────────────────────────────────────
setInterval(()=>{
    const now = Date.now();
    rooms.forEach((r,rid)=>{
        r.members.forEach((m,uid)=>{
            if(now-m.lastSeen>60000) {
                r.members.delete(uid);
                udpKeys.delete(`${rid}:${uid}`);
            }
        });
        if (!r.members.size && now-r.lastActivity>300000) rooms.delete(rid);
    });
    udpMap.forEach((v,k)=>{ if(now-v.t>120000) udpMap.delete(k); });
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
