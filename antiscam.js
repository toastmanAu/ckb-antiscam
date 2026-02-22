/**
 * CKB Anti-Scam Bot
 * Protects the @NervosUnofficial Telegram group from fake moderator scams.
 *
 * Detection vectors:
 *   1. Name similarity — Levenshtein distance ≤ 2 from any real mod name
 *   2. Profile photo similarity — perceptual hash comparison (phash)
 *   3. DM-baiting messages — pattern matching for "dm me", "contact me privately" etc.
 *
 * Actions:
 *   - Scam JOIN: ban + delete join message + alert admins
 *   - Scam MESSAGE: delete + ban + alert admins (configurable: warn-first mode)
 *   - All bans logged to ban-log.json
 *
 * Requirements:
 *   - Bot must be an admin with: Ban users, Delete messages, Restrict members
 *   - config.json must list real mod usernames and their Telegram user IDs
 */

'use strict';

const TelegramBot = require('node-telegram-bot-api');
const Levenshtein = require('fast-levenshtein');
const sharp       = require('sharp');
const axios       = require('axios');
const fs          = require('fs');
const path        = require('path');

// ─── Config ──────────────────────────────────────────────────────────────────

const CONFIG_PATH  = path.join(__dirname, 'config.json');
const BANLOG_PATH  = path.join(__dirname, 'ban-log.json');
const CACHE_DIR    = path.join(__dirname, 'photo-cache');

if (!fs.existsSync(CONFIG_PATH)) {
    console.error('❌ config.json not found. Copy config.example.json and fill it in.');
    process.exit(1);
}

const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const BOT_TOKEN   = config.bot_token;
const CHAT_ID     = config.chat_id;     // e.g. -1001338982855
const ALERT_CHAT  = config.alert_chat || config.chat_id; // where to send ban alerts
const MODS        = config.mods;        // array of { name, username, user_id }
const WARN_FIRST  = config.warn_first !== false; // default true: warn before ban on messages

// Similarity thresholds
const NAME_DIST_THRESHOLD  = config.name_dist_threshold  || 2;   // Levenshtein ≤ 2
const PHOTO_HASH_THRESHOLD = config.photo_hash_threshold || 10;  // hamming ≤ 10 = similar

// DM-baiting patterns (case-insensitive)
const DM_BAIT_PATTERNS = [
    /\bdm\s*me\b/i,
    /\bpm\s*me\b/i,
    /contact\s*me\s*(privately|via dm|in dm|through dm)/i,
    /send\s*me\s*a\s*(dm|message|pm)/i,
    /message\s*me\s*(privately|in private|in dm)/i,
    /reach\s*me\s*(in|via|through)\s*(dm|private)/i,
    /\bprivate\s*message\s*me\b/i,
    /write\s*to\s*me\s*(directly|privately|in dm)/i,
    /contact\s*me\s*for\s*(support|help|assistance)/i,
    /\bi.*official.*admin\b/i,
    /\bi.*mod(erator)?\b.*\bhelp\b/i,
    /\bofficially\s*(contact|support)\b/i,
];

// ─── Setup ───────────────────────────────────────────────────────────────────

if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// In-memory warn tracker { userId: warnCount }
const warnings = new Map();
// Known good users (admins + confirmed mods) - populated at startup
const confirmedMods = new Set();
// Photo hashes of real mods { userId: phash }
const modPhotoHashes = new Map();

// ─── Logging ─────────────────────────────────────────────────────────────────

function log(level, msg, data = {}) {
    const ts = new Date().toISOString();
    console.log(`[${ts}] [${level}] ${msg}`, Object.keys(data).length ? data : '');
}

function appendBanLog(entry) {
    let banLog = [];
    if (fs.existsSync(BANLOG_PATH)) {
        try { banLog = JSON.parse(fs.readFileSync(BANLOG_PATH, 'utf8')); } catch {}
    }
    banLog.push({ ...entry, ts: new Date().toISOString() });
    fs.writeFileSync(BANLOG_PATH, JSON.stringify(banLog, null, 2));
}

// ─── Perceptual Hash (pHash) ──────────────────────────────────────────────────
// Simple 8x8 DCT-based pHash in pure Node — no native deps beyond sharp.

async function computePhash(imageBuffer) {
    // Resize to 32x32 greyscale, then 8x8 average hash (fast, good enough)
    const pixels = await sharp(imageBuffer)
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
    let x = a ^ b;
    let dist = 0;
    while (x) { dist += Number(x & 1n); x >>= 1n; }
    return dist;
}

async function downloadPhoto(fileId) {
    try {
        const file = await bot.getFile(fileId);
        const url  = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;
        const resp = await axios.get(url, { responseType: 'arraybuffer', timeout: 8000 });
        return Buffer.from(resp.data);
    } catch (e) {
        log('WARN', 'Failed to download photo', { fileId, err: e.message });
        return null;
    }
}

async function getPhotoHash(userId) {
    try {
        const photos = await bot.getUserProfilePhotos(userId, { limit: 1 });
        if (!photos.total_count) return null;
        const fileId = photos.photos[0].slice(-1)[0].file_id; // largest size
        const buf    = await downloadPhoto(fileId);
        if (!buf) return null;
        return await computePhash(buf);
    } catch (e) {
        log('WARN', 'getPhotoHash failed', { userId, err: e.message });
        return null;
    }
}

// ─── Mod photo hash cache (load at startup) ───────────────────────────────────

async function loadModHashes() {
    log('INFO', `Loading photo hashes for ${MODS.length} mods...`);
    for (const mod of MODS) {
        confirmedMods.add(mod.user_id);
        const hash = await getPhotoHash(mod.user_id);
        if (hash !== null) {
            modPhotoHashes.set(mod.user_id, hash);
            log('INFO', `  ✓ ${mod.name} (${mod.username}) hash cached`);
        } else {
            log('WARN', `  ✗ ${mod.name} — no photo or couldn't fetch`);
        }
        await delay(500); // rate limit
    }
    log('INFO', `Mod hashes loaded: ${modPhotoHashes.size}/${MODS.length}`);
}

// ─── Name similarity check ────────────────────────────────────────────────────

function nameSimilarityScore(name) {
    if (!name) return { suspicious: false };
    const norm = name.toLowerCase().trim();

    for (const mod of MODS) {
        const modName = mod.name.toLowerCase().trim();
        const dist = Levenshtein.get(norm, modName);

        // Also check if name CONTAINS the mod name (e.g. "Phill | Admin")
        const contains = norm.includes(modName) || modName.includes(norm);

        if (dist <= NAME_DIST_THRESHOLD || (contains && norm !== modName)) {
            return {
                suspicious: true,
                matchedMod: mod.name,
                distance: dist,
                reason: dist <= NAME_DIST_THRESHOLD
                    ? `Name "${name}" is ${dist} edit(s) from mod "${mod.name}"`
                    : `Name "${name}" contains/matches mod name "${mod.name}"`,
            };
        }

        // Check username similarly
        if (mod.username) {
            const modUser = mod.username.toLowerCase().replace('@', '');
            const userNorm = norm.replace('@', '');
            const udist = Levenshtein.get(userNorm, modUser);
            if (udist > 0 && udist <= NAME_DIST_THRESHOLD) {
                return {
                    suspicious: true,
                    matchedMod: mod.name,
                    distance: udist,
                    reason: `Username "${name}" is ${udist} edit(s) from mod @${mod.username}`,
                };
            }
        }
    }
    return { suspicious: false };
}

// ─── Photo similarity check ───────────────────────────────────────────────────

async function photoSimilarityScore(userId) {
    if (!modPhotoHashes.size) return { suspicious: false };
    const userHash = await getPhotoHash(userId);
    if (userHash === null) return { suspicious: false }; // no photo = skip

    for (const [modId, modHash] of modPhotoHashes) {
        const dist = hammingDistance(userHash, modHash);
        if (dist <= PHOTO_HASH_THRESHOLD) {
            const mod = MODS.find(m => m.user_id === modId);
            return {
                suspicious: true,
                matchedMod: mod ? mod.name : String(modId),
                distance: dist,
                reason: `Profile photo is similar to mod "${mod ? mod.name : modId}" (hamming=${dist})`,
            };
        }
    }
    return { suspicious: false };
}

// ─── DM bait detection ────────────────────────────────────────────────────────

function isDmBait(text) {
    if (!text) return false;
    return DM_BAIT_PATTERNS.some(p => p.test(text));
}

// ─── Claim-to-be-mod detection ───────────────────────────────────────────────

function claimsToBeAdmin(text) {
    if (!text) return false;
    const patterns = [
        /\bi('?m| am)\s+(a\s+)?(mod|moderator|admin|official|team)/i,
        /\bofficial\s+(team|support|moderator|admin)\b/i,
        /\bnervos\s+(official|support|admin|mod)\b/i,
        /\bckb\s+(official|support|admin|mod)\b/i,
    ];
    return patterns.some(p => p.test(text));
}

// ─── Ban action ───────────────────────────────────────────────────────────────

async function banUser(userId, username, reason, triggeredBy = 'auto') {
    try {
        await bot.banChatMember(CHAT_ID, userId);
        log('BAN', `Banned user ${userId} (${username})`, { reason });

        appendBanLog({ userId, username, reason, triggeredBy });

        const alert = [
            `🚫 *Scammer banned*`,
            ``,
            `👤 User: ${username ? '@' + username : 'no username'} (ID: \`${userId}\`)`,
            `📋 Reason: ${reason}`,
            `🤖 Triggered by: ${triggeredBy}`,
        ].join('\n');

        await bot.sendMessage(ALERT_CHAT, alert, { parse_mode: 'Markdown' });
        return true;
    } catch (e) {
        log('ERROR', 'Ban failed', { userId, err: e.message });
        return false;
    }
}

async function deleteMessage(chatId, messageId) {
    try {
        await bot.deleteMessage(chatId, messageId);
    } catch (e) {
        log('WARN', 'Delete message failed', { messageId, err: e.message });
    }
}

// ─── Full user check (for new members) ───────────────────────────────────────

async function checkUser(userId, firstName, lastName, username) {
    if (confirmedMods.has(userId)) return; // skip real mods

    const fullName = [firstName, lastName].filter(Boolean).join(' ');
    const checks   = [];

    // 1. Name check (fast)
    const nameCheck = nameSimilarityScore(fullName);
    if (nameCheck.suspicious) checks.push(nameCheck);

    // Also check display name vs username
    if (username) {
        const unCheck = nameSimilarityScore(username);
        if (unCheck.suspicious) checks.push(unCheck);
    }

    // 2. Photo check (slower — only if name looks suspicious or as extra check)
    const photoCheck = await photoSimilarityScore(userId);
    if (photoCheck.suspicious) checks.push(photoCheck);

    if (checks.length > 0) {
        const reasons = checks.map(c => c.reason).join('; ');
        log('ALERT', `Suspicious user detected`, { userId, fullName, username, reasons });
        return { suspicious: true, reasons };
    }
    return { suspicious: false };
}

// ─── Event handlers ───────────────────────────────────────────────────────────

// New member joined
bot.on('new_chat_members', async (msg) => {
    if (String(msg.chat.id) !== String(CHAT_ID)) return;

    for (const member of msg.new_chat_members) {
        if (member.is_bot) continue;
        const userId   = member.id;
        const username = member.username;
        const first    = member.first_name || '';
        const last     = member.last_name  || '';

        log('INFO', `New member: ${first} ${last} (@${username}) [${userId}]`);

        const result = await checkUser(userId, first, last, username);
        if (result && result.suspicious) {
            // Delete join message
            await deleteMessage(CHAT_ID, msg.message_id);
            // Ban immediately
            await banUser(userId, username,
                `Fake mod on join: ${result.reasons}`, 'join-check');
        }
    }
});

// Messages
bot.on('message', async (msg) => {
    if (!msg.chat || String(msg.chat.id) !== String(CHAT_ID)) return;
    if (!msg.from || msg.from.is_bot) return;

    const userId   = msg.from.id;
    const username = msg.from.username;
    const first    = msg.from.first_name || '';
    const last     = msg.from.last_name  || '';
    const text     = msg.text || msg.caption || '';
    const msgId    = msg.message_id;

    if (confirmedMods.has(userId)) return; // skip real mods

    // Check for DM bait or admin claim
    const baiting = isDmBait(text);
    const claiming = claimsToBeAdmin(text);

    if (baiting || claiming) {
        log('ALERT', `DM bait/claim from ${userId}`, { text: text.slice(0, 100) });

        // Also run user check to see if they look like a fake mod
        const userCheck = await checkUser(userId, first, last, username);

        if (userCheck.suspicious || claiming) {
            // High confidence — delete + ban immediately
            await deleteMessage(CHAT_ID, msgId);
            await banUser(userId, username,
                [
                    baiting  ? 'DM-baiting message' : null,
                    claiming ? 'Claims to be admin/mod' : null,
                    userCheck.suspicious ? `Fake mod appearance: ${userCheck.reasons}` : null,
                ].filter(Boolean).join('; '),
                'message-check');
        } else if (baiting && WARN_FIRST) {
            // DM bait only, warn first
            const warnCount = (warnings.get(userId) || 0) + 1;
            warnings.set(userId, warnCount);

            if (warnCount >= 2) {
                await deleteMessage(CHAT_ID, msgId);
                await banUser(userId, username,
                    `Repeated DM-baiting after warning (${warnCount}x)`, 'warn-threshold');
            } else {
                await deleteMessage(CHAT_ID, msgId);
                try {
                    await bot.sendMessage(CHAT_ID,
                        `⚠️ @${username || first} — asking people to DM you is not allowed here. ` +
                        `This is warning 1/${2}. Next violation = ban.`,
                        { reply_to_message_id: msgId }
                    );
                } catch {}
            }
        } else {
            // No warn-first mode, just ban
            await deleteMessage(CHAT_ID, msgId);
            await banUser(userId, username, 'DM-baiting message', 'message-check');
        }
    }
});

// Handle left/banned chat member (clean up warnings)
bot.on('left_chat_member', (msg) => {
    if (msg.left_chat_member) {
        warnings.delete(msg.left_chat_member.id);
    }
});

// ─── /checkme command (for testing — admin only) ──────────────────────────────

bot.onText(/\/checkme/, async (msg) => {
    if (String(msg.chat.id) !== String(CHAT_ID)) return;
    if (!confirmedMods.has(msg.from.id)) return; // mods only

    const { from } = msg;
    const result = await checkUser(from.id, from.first_name, from.last_name, from.username);
    await bot.sendMessage(CHAT_ID,
        result.suspicious
            ? `⚠️ Would flag: ${result.reasons}`
            : `✅ Looks clean (name distance OK, photo OK)`,
        { reply_to_message_id: msg.message_id }
    );
});

// ─── /refreshhashes command (update mod photo hashes) ────────────────────────

bot.onText(/\/refreshhashes/, async (msg) => {
    if (String(msg.chat.id) !== String(CHAT_ID)) return;
    if (!confirmedMods.has(msg.from.id)) return;

    await bot.sendMessage(CHAT_ID, '🔄 Refreshing mod photo hashes...', {});
    modPhotoHashes.clear();
    await loadModHashes();
    await bot.sendMessage(CHAT_ID,
        `✅ Hashes refreshed for ${modPhotoHashes.size} mods.`);
});

// ─── /bans command (show recent bans) ────────────────────────────────────────

bot.onText(/\/bans(?:\s+(\d+))?/, async (msg, match) => {
    if (!confirmedMods.has(msg.from.id)) return;
    const n = parseInt(match[1] || '5');
    let banLog = [];
    if (fs.existsSync(BANLOG_PATH)) {
        try { banLog = JSON.parse(fs.readFileSync(BANLOG_PATH, 'utf8')); } catch {}
    }
    const recent = banLog.slice(-n).reverse();
    if (!recent.length) {
        return bot.sendMessage(CHAT_ID, '📋 No bans logged yet.');
    }
    const lines = recent.map((b, i) =>
        `${i+1}. @${b.username || 'n/a'} (${b.userId})\n   ${b.reason}\n   ${b.ts}`
    ).join('\n\n');
    await bot.sendMessage(CHAT_ID,
        `📋 *Last ${recent.length} bans:*\n\n${lines}`,
        { parse_mode: 'Markdown' });
});

// ─── Startup ──────────────────────────────────────────────────────────────────

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
    log('INFO', '🛡️  CKB Anti-Scam Bot starting...');
    log('INFO', `Group: ${CHAT_ID}`);
    log('INFO', `Mods: ${MODS.map(m => m.name).join(', ')}`);
    log('INFO', `Name threshold: ≤${NAME_DIST_THRESHOLD} edits`);
    log('INFO', `Photo threshold: ≤${PHOTO_HASH_THRESHOLD} hamming`);
    log('INFO', `Warn first: ${WARN_FIRST}`);

    // Verify bot is admin
    try {
        const me = await bot.getMe();
        log('INFO', `Bot: @${me.username} (${me.id})`);

        const chatMember = await bot.getChatMember(CHAT_ID, me.id);
        if (!['administrator', 'creator'].includes(chatMember.status)) {
            log('ERROR', '❌ Bot is NOT an admin in this group. Ban/delete will fail.');
        } else {
            log('INFO', '✅ Bot is admin');
        }
    } catch (e) {
        log('ERROR', 'Startup check failed', { err: e.message });
    }

    // Load mod photo hashes
    await loadModHashes();

    log('INFO', '✅ Bot running — watching for scammers');

    // Reload hashes every 6 hours (mods can change their photos)
    setInterval(async () => {
        log('INFO', 'Scheduled hash refresh...');
        modPhotoHashes.clear();
        await loadModHashes();
    }, 6 * 60 * 60 * 1000);
}

main().catch(e => {
    log('ERROR', 'Fatal error', { err: e.message });
    process.exit(1);
});
