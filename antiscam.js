/**
 * CKB Anti-Scam Bot — @Wyltek_PoPo_Bot
 * Protects the @NervosUnofficial Telegram group from fake moderator scams.
 *
 * Detection vectors:
 *   1. Name similarity  — Levenshtein ≤ 2 edits from any real mod name/alias
 *   2. Profile photo    — perceptual hash similarity (hamming ≤ 10)
 *   3. DM-bait messages — regex patterns on all messages
 *   4. Admin claims     — "I am the official mod" style claims
 *
 * Uses raw https module (no node-telegram-bot-api) for compatibility.
 */

'use strict';

// Force IPv4 DNS resolution — Telegram IPv6 unreachable from this host
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const Levenshtein = require('fast-levenshtein');
const sharp = require('sharp');

// ─── Config ───────────────────────────────────────────────────────────────────

const CONFIG_PATH = path.join(__dirname, 'config.json');
const BANLOG_PATH = path.join(__dirname, 'ban-log.json');
const CACHE_DIR   = path.join(__dirname, 'photo-cache');

if (!fs.existsSync(CONFIG_PATH)) {
    console.error('❌ config.json not found.');
    process.exit(1);
}

const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const BOT_TOKEN   = config.bot_token;
const CHAT_ID     = String(config.chat_id);
const ALERT_CHAT  = String(config.alert_chat || config.chat_id);
const MODS        = config.mods || [];
const WARN_FIRST  = config.warn_first !== false;
const DRY_RUN     = config.dry_run === true;   // log-only mode, no bans/deletes
const NAME_THRESH = config.name_dist_threshold  || 2;
const PHOTO_THRESH= config.photo_hash_threshold || 10;

if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

// ─── DM-bait patterns ─────────────────────────────────────────────────────────

const DM_BAIT_PATTERNS = [
    /\bdm\s*me\b/i,
    /\bpm\s*me\b/i,
    /contact\s*me\s*(privately|via dm|in dm|through dm)/i,
    /send\s*me\s*a\s*(dm|message|pm)/i,
    /message\s*me\s*(privately|in private|in dm)/i,
    /reach\s*me\s*(in|via|through)\s*(dm|private)/i,
    /\bprivate\s*message\s*me\b/i,
    /write\s*to\s*me\s*(directly|privately)/i,
    /contact\s*me\s*for\s*(support|help|assistance)/i,
    /\bi.*official.*admin\b/i,
    /\bofficially\s*(contact|support)\b/i,
];

const ADMIN_CLAIM_PATTERNS = [
    /\bi('?m| am)\s+(a\s+)?(mod|moderator|admin|official|team)\b/i,
    /\bofficial\s+(team|support|moderator|admin)\b/i,
    /\bnervos\s+(official|support|admin|mod)\b/i,
    /\bckb\s+(official|support|admin|mod)\b/i,
];

// ─── State ────────────────────────────────────────────────────────────────────

const confirmedMods  = new Set(MODS.map(m => m.user_id));
const modPhotoHashes = new Map();  // userId → BigInt hash
const warnings       = new Map();  // userId → warn count
let   lastUpdateId   = 0;

// ─── Logging ─────────────────────────────────────────────────────────────────

function log(level, msg, data) {
    const ts = new Date().toISOString();
    const extra = data ? ' ' + JSON.stringify(data) : '';
    console.log(`[${ts}] [${level}] ${msg}${extra}`);
}

function appendBanLog(entry) {
    let banLog = [];
    if (fs.existsSync(BANLOG_PATH)) {
        try { banLog = JSON.parse(fs.readFileSync(BANLOG_PATH, 'utf8')); } catch {}
    }
    banLog.push({ ...entry, ts: new Date().toISOString() });
    fs.writeFileSync(BANLOG_PATH, JSON.stringify(banLog, null, 2));
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function httpsGet(url) {
    return new Promise((resolve, reject) => {
        const isHttps = url.startsWith('https');
        const mod = isHttps ? https : http;
        mod.get(url, { timeout: 10000 }, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        }).on('error', reject).on('timeout', () => reject(new Error('timeout')));
    });
}

function tgApi(method, params = {}) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify(params);
        const req = https.request(
            {
                hostname: 'api.telegram.org',
                port: 443,
                path: `/bot${BOT_TOKEN}/${method}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                },
                timeout: 35000,
            },
            (res) => {
                const chunks = [];
                res.on('data', c => chunks.push(c));
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(Buffer.concat(chunks).toString());
                        if (parsed.ok) resolve(parsed.result);
                        else reject(new Error(parsed.description || 'TG API error'));
                    } catch (e) { reject(e); }
                });
                res.on('error', (e) => reject(new Error(e.message || String(e))));
            }
        );
        req.on('error', (e) => reject(new Error(e.message || String(e))));
        req.on('timeout', () => { req.destroy(); reject(new Error('request timeout')); });
        req.write(body);
        req.end();
    });
}

// ─── Perceptual hash ──────────────────────────────────────────────────────────

async function computePhash(buf) {
    const pixels = await sharp(buf)
        .resize(8, 8, { fit: 'fill' })
        .greyscale()
        .raw()
        .toBuffer();
    const avg = pixels.reduce((s, v) => s + v, 0) / pixels.length;
    let hash = 0n;
    for (let i = 0; i < 64; i++) {
        if (pixels[i] >= avg) hash |= (1n << BigInt(i));
    }
    return hash;
}

function hammingDistance(a, b) {
    let x = a ^ b, d = 0;
    while (x) { d += Number(x & 1n); x >>= 1n; }
    return d;
}

async function getPhotoHash(userId) {
    try {
        const photos = await tgApi('getUserProfilePhotos', { user_id: userId, limit: 1 });
        if (!photos.total_count) return null;
        const fileId = photos.photos[0].slice(-1)[0].file_id;
        const file   = await tgApi('getFile', { file_id: fileId });
        const url    = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;
        const buf    = await httpsGet(url);
        return await computePhash(buf);
    } catch (e) {
        log('WARN', `getPhotoHash failed for ${userId}`, { err: e.message });
        return null;
    }
}

async function loadModHashes() {
    log('INFO', `Loading photo hashes for ${MODS.length} mod(s)...`);
    for (const mod of MODS) {
        const hash = await getPhotoHash(mod.user_id);
        if (hash !== null) {
            modPhotoHashes.set(mod.user_id, hash);
            log('INFO', `  ✓ ${mod.name} hash cached`);
        } else {
            log('WARN', `  ✗ ${mod.name} — no photo`);
        }
        await delay(600);
    }
    log('INFO', `Hashes loaded: ${modPhotoHashes.size}/${MODS.length}`);
}

// ─── Detection ────────────────────────────────────────────────────────────────

function nameSimilarityScore(name) {
    if (!name) return { suspicious: false };
    const norm = name.toLowerCase().trim();

    for (const mod of MODS) {
        const variants = [mod.name, ...(mod.aliases || [])];
        for (const variant of variants) {
            const modName = variant.toLowerCase().trim();
            const dist    = Levenshtein.get(norm, modName);
            const contains = norm.includes(modName) || modName.includes(norm);
            if (dist <= NAME_THRESH || (contains && norm !== modName)) {
                return {
                    suspicious: true,
                    matchedMod: mod.name,
                    reason: dist <= NAME_THRESH
                        ? `Name "${name}" is ${dist} edit(s) from mod "${variant}"`
                        : `Name "${name}" contains mod name "${variant}"`,
                };
            }
        }
        if (mod.username) {
            const modUser  = mod.username.toLowerCase().replace('@', '');
            const userNorm = norm.replace('@', '');
            const udist    = Levenshtein.get(userNorm, modUser);
            if (udist > 0 && udist <= NAME_THRESH) {
                return {
                    suspicious: true,
                    matchedMod: mod.name,
                    reason: `Username "${name}" is ${udist} edit(s) from @${mod.username}`,
                };
            }
        }
    }
    return { suspicious: false };
}

async function photoSimilarityScore(userId) {
    if (!modPhotoHashes.size) return { suspicious: false };
    const userHash = await getPhotoHash(userId);
    if (userHash === null) return { suspicious: false };

    for (const [modId, modHash] of modPhotoHashes) {
        const dist = hammingDistance(userHash, modHash);
        if (dist <= PHOTO_THRESH) {
            const mod = MODS.find(m => m.user_id === modId);
            return {
                suspicious: true,
                matchedMod: mod ? mod.name : String(modId),
                reason: `Profile photo similar to ${mod ? mod.name : modId} (hamming=${dist})`,
            };
        }
    }
    return { suspicious: false };
}

function isDmBait(text)      { return DM_BAIT_PATTERNS.some(p => p.test(text)); }
function claimsAdmin(text)   { return ADMIN_CLAIM_PATTERNS.some(p => p.test(text)); }

async function checkUser(userId, firstName, lastName, username) {
    if (confirmedMods.has(userId)) return { suspicious: false };
    const fullName = [firstName, lastName].filter(Boolean).join(' ');
    const checks   = [];
    const nameCheck = nameSimilarityScore(fullName);
    if (nameCheck.suspicious) checks.push(nameCheck);
    if (username) {
        const unCheck = nameSimilarityScore(username);
        if (unCheck.suspicious) checks.push(unCheck);
    }
    const photoCheck = await photoSimilarityScore(userId);
    if (photoCheck.suspicious) checks.push(photoCheck);
    if (checks.length > 0) {
        return { suspicious: true, reasons: checks.map(c => c.reason).join('; ') };
    }
    return { suspicious: false };
}

// ─── Actions ──────────────────────────────────────────────────────────────────

async function banUser(userId, username, reason, trigger) {
    if (DRY_RUN) {
        log('DRY-RUN', `Would ban ${userId} (@${username})`, { reason, trigger });
        appendBanLog({ userId, username, reason, trigger, dry_run: true });
        return;
    }
    try {
        await tgApi('banChatMember', { chat_id: CHAT_ID, user_id: userId });
        log('BAN', `Banned ${userId} (@${username})`, { reason });
        appendBanLog({ userId, username, reason, trigger });
        const alert =
            `🚫 *Scammer banned*\n\n` +
            `👤 ${username ? '@' + username : 'no username'} (ID: \`${userId}\`)\n` +
            `📋 ${reason}\n` +
            `🤖 Trigger: ${trigger}`;
        await tgApi('sendMessage', { chat_id: ALERT_CHAT, text: alert, parse_mode: 'Markdown' });
    } catch (e) {
        log('ERROR', 'Ban failed', { userId, err: e.message });
    }
}

async function deleteMsg(chatId, messageId) {
    if (DRY_RUN) { log('DRY-RUN', `Would delete message ${messageId}`); return; }
    try { await tgApi('deleteMessage', { chat_id: chatId, message_id: messageId }); }
    catch (e) { log('WARN', 'Delete failed', { messageId, err: e.message }); }
}

async function sendMsg(chatId, text, extra = {}) {
    try { await tgApi('sendMessage', { chat_id: chatId, text, ...extra }); }
    catch (e) { log('WARN', 'Send failed', { err: e.message }); }
}

// ─── Update handlers ──────────────────────────────────────────────────────────

async function handleNewMembers(msg) {
    for (const member of (msg.new_chat_members || [])) {
        if (member.is_bot) continue;
        const { id: userId, username, first_name: first, last_name: last } = member;
        log('INFO', `New member: ${first} ${last || ''} (@${username}) [${userId}]`);
        const result = await checkUser(userId, first, last, username);
        if (result.suspicious) {
            await deleteMsg(CHAT_ID, msg.message_id);
            await banUser(userId, username,
                `Fake mod on join: ${result.reasons}`, 'join-check');
        }
    }
}

async function handleMessage(msg) {
    const from = msg.from;
    if (!from || from.is_bot) return;
    const { id: userId, username, first_name: first, last_name: last } = from;
    const text  = msg.text || msg.caption || '';
    const msgId = msg.message_id;

    if (confirmedMods.has(userId)) return;
    if (!text) return;

    const baiting  = isDmBait(text);
    const claiming = claimsAdmin(text);

    if (!baiting && !claiming) return;

    log('ALERT', `Suspicious message from ${userId}`, { text: text.slice(0, 120) });

    const userCheck = await checkUser(userId, first, last, username);

    if (claiming || userCheck.suspicious) {
        // High confidence — immediate ban
        await deleteMsg(CHAT_ID, msgId);
        const reasons = [
            baiting  ? 'DM-baiting' : null,
            claiming ? 'Claims to be admin' : null,
            userCheck.suspicious ? userCheck.reasons : null,
        ].filter(Boolean).join('; ');
        await banUser(userId, username, reasons, 'message-check');

    } else if (baiting && WARN_FIRST) {
        const warnCount = (warnings.get(userId) || 0) + 1;
        warnings.set(userId, warnCount);
        await deleteMsg(CHAT_ID, msgId);
        if (warnCount >= 2) {
            await banUser(userId, username,
                `Repeated DM-baiting after ${warnCount - 1} warning(s)`, 'warn-threshold');
        } else {
            await sendMsg(CHAT_ID,
                `⚠️ ${username ? '@' + username : first} — asking people to DM you is not allowed here. ` +
                `Warning 1/2. Next offence = ban.`);
        }
    } else {
        await deleteMsg(CHAT_ID, msgId);
        await banUser(userId, username, 'DM-baiting message', 'message-check');
    }
}

async function handleCommand(msg) {
    if (!confirmedMods.has(msg.from.id)) return;
    const text = msg.text || '';
    const chatId = String(msg.chat.id);

    if (text.startsWith('/bans')) {
        const n = parseInt(text.split(' ')[1] || '5');
        let banLog = [];
        if (fs.existsSync(BANLOG_PATH)) {
            try { banLog = JSON.parse(fs.readFileSync(BANLOG_PATH, 'utf8')); } catch {}
        }
        const recent = banLog.slice(-n).reverse();
        if (!recent.length) return sendMsg(chatId, '📋 No bans logged yet.');
        const lines = recent.map((b, i) =>
            `${i+1}. @${b.username || 'n/a'} (${b.userId})\n   ${b.reason}\n   ${b.ts}`
        ).join('\n\n');
        return sendMsg(chatId, `📋 *Last ${recent.length} bans:*\n\n${lines}`, { parse_mode: 'Markdown' });
    }

    if (text.startsWith('/refreshhashes')) {
        await sendMsg(chatId, '🔄 Refreshing mod photo hashes...');
        modPhotoHashes.clear();
        await loadModHashes();
        return sendMsg(chatId, `✅ Hashes refreshed for ${modPhotoHashes.size} mod(s).`);
    }

    if (text.startsWith('/checkme')) {
        const { from: f } = msg;
        const result = await checkUser(f.id, f.first_name, f.last_name, f.username);
        return sendMsg(chatId,
            result.suspicious
                ? `⚠️ Would flag: ${result.reasons}`
                : `✅ Looks clean (name OK, photo OK)`,
            { reply_to_message_id: msg.message_id });
    }

    if (text.startsWith('/status')) {
        return sendMsg(chatId,
            `🛡️ PoPo Bot active\n` +
            `Mods protected: ${MODS.length}\n` +
            `Photo hashes cached: ${modPhotoHashes.size}\n` +
            `Active warnings: ${warnings.size}\n` +
            `Last update ID: ${lastUpdateId}`);
    }
}

// ─── Polling loop ─────────────────────────────────────────────────────────────

async function poll() {
    try {
        const updates = await tgApi('getUpdates', {
            offset: lastUpdateId + 1,
            timeout: 30,
            allowed_updates: ['message', 'chat_member'],
        });

        for (const update of (updates || [])) {
            lastUpdateId = update.update_id;
            const msg = update.message;
            if (!msg) continue;

            const chatId = String(msg.chat.id);
            if (chatId !== CHAT_ID && chatId !== ALERT_CHAT) {
                // Private message to bot — only handle commands from mods
                if (msg.text && msg.text.startsWith('/')) {
                    await handleCommand(msg);
                }
                continue;
            }

            if (msg.new_chat_members) {
                await handleNewMembers(msg);
            } else if (msg.text || msg.caption) {
                if (msg.text && msg.text.startsWith('/')) {
                    await handleCommand(msg);
                } else {
                    await handleMessage(msg);
                }
            }
        }
    } catch (e) {
        const errMsg = e.message || String(e);
        // AggregateError usually means a conflict (another instance polling)
        if (errMsg.includes('AggregateError') || errMsg.includes('Conflict')) {
            log('WARN', 'Poll conflict — another instance may be running, waiting 10s');
            await delay(10000);
        } else {
            log('WARN', 'Poll error', { err: errMsg });
            await delay(5000);
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
    log('INFO', '🛡️  PoPo Bot (CKB Anti-Scam) starting...');
    log('INFO', `Group: ${CHAT_ID}`);
    log('INFO', `Mods: ${MODS.map(m => `${m.name} (@${m.username})`).join(', ')}`);

    // Brief startup delay to avoid conflicts with previous instance
    await delay(3000);

    // Verify bot identity (retry up to 5x for startup network settling)
    let me = null;
    for (let attempt = 1; attempt <= 5; attempt++) {
        try {
            me = await tgApi('getMe');
            log('INFO', `Bot: @${me.username} (${me.id})`);
            break;
        } catch (e) {
            log('WARN', `getMe attempt ${attempt}/5 failed`, { err: e.message });
            if (attempt === 5) {
                log('ERROR', 'getMe failed after 5 attempts — exiting');
                process.exit(1);
            }
            await delay(5000);
        }
    }

    // Load mod photo hashes
    await loadModHashes();

    // Refresh hashes every 6 hours
    setInterval(async () => {
        log('INFO', 'Scheduled photo hash refresh...');
        modPhotoHashes.clear();
        await loadModHashes();
    }, 6 * 60 * 60 * 1000);

    log('INFO', '✅ Polling for updates...');
    if (DRY_RUN) log('INFO', '⚠️  DRY-RUN MODE — logging only, no bans or deletes');

    // Long-polling loop
    while (true) {
        await poll();
    }
}

main().catch(e => {
    log('ERROR', 'Fatal', { err: e.message });
    process.exit(1);
});
