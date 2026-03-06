/**
 * CKB Anti-Scam Bot — @Wyltek_PoPo_Bot
 * Protects Nervos Nation from scammers, spam bots, and honeypot accounts.
 *
 * Detection vectors:
 *   1. Name similarity      — Levenshtein ≤ 2 edits from any real mod name/alias
 *   2. Profile photo        — perceptual hash similarity (hamming ≤ 10)
 *   3. DM-bait messages     — regex patterns on all messages
 *   4. Admin claims         — "I am the official mod" style claims
 *   5. Trading/invest spam  — weighted signal scoring (26 patterns)
 *   6. Honeypot accounts    — ❤️-reaction spam without posting (porn bots)
 *   7. Bot behaviour score  — join/leave timing, message cadence, forwards,
 *                             copy-paste, user_id freshness, language mismatch
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
const CACHE_DIR   = path.join(__dirname, 'photo-cache');

if (!fs.existsSync(CONFIG_PATH)) {
    console.error('❌ config.json not found.');
    process.exit(1);
}

const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const BOT_TOKEN   = config.bot_token;
const MODS        = config.mods || [];
const WARN_FIRST  = config.warn_first !== false;
const DRY_RUN     = config.dry_run === true;
const LEARN_MODE  = config.learn_mode === true;
const NAME_THRESH = config.name_dist_threshold  || 2;
const PHOTO_THRESH= config.photo_hash_threshold || 10;

// ─── Multi-group support ──────────────────────────────────────────────────────
//
// Config supports either legacy single-group:
//   { "chat_id": "-100xxx", "alert_chat": "-100yyy" }
// or new multi-group:
//   { "groups": [ { "id": "-100xxx", "name": "Nervos Nation", "alert_chat": "-100yyy" }, ... ] }
//
// Each group gets its own data directory under data/<groupId>/
// containing: ban-log.json, event-log.jsonl, photo-cache/

function buildGroups() {
    if (config.groups && Array.isArray(config.groups)) {
        return config.groups.map(g => ({
            id:         String(g.id),
            name:       g.name || String(g.id),
            alertChat:  String(g.alert_chat || g.id),
            dryRun:     g.dry_run !== undefined ? g.dry_run : DRY_RUN,
            dataDir:    path.join(__dirname, 'data', String(g.id).replace(/^-/, '')),
        }));
    }
    // Legacy single-group
    const gid = String(config.chat_id);
    return [{
        id:        gid,
        name:      config.group_name || 'Group',
        alertChat: String(config.alert_chat || gid),
        dryRun:    DRY_RUN,
        dataDir:   path.join(__dirname, 'data', gid.replace(/^-/, '')),
    }];
}

const GROUPS = buildGroups();
const GROUP_IDS = new Set(GROUPS.map(g => g.id));

// Convenience: look up group config by chat id
function getGroup(chatId) {
    return GROUPS.find(g => g.id === String(chatId)) || null;
}

// Per-group helpers
function banlogPath(grp)        { return path.join(grp.dataDir, 'ban-log.json'); }
function eventlogPath(grp)      { return path.join(grp.dataDir, 'event-log.jsonl'); }
function predictionsPath(grp)   { return path.join(grp.dataDir, 'predictions.jsonl'); }
function adminActionsPath(grp)  { return path.join(grp.dataDir, 'admin-actions.jsonl'); }
function cacheDir(grp)          { return path.join(grp.dataDir, 'photo-cache'); }

// Initialise data dirs
for (const grp of GROUPS) {
    fs.mkdirSync(grp.dataDir, { recursive: true });
    fs.mkdirSync(cacheDir(grp), { recursive: true });
}

// Legacy shims — used by code that hasn't been group-parameterised yet
// (photo hash cache — shared across groups since a user is the same person everywhere)
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

// ─── Trading platform / investment spam patterns ───────────────────────────
//
// Signatures derived from the "genuine trading platform" spam seen in CKB
// community groups. These messages typically:
//   1. Claim to use a "genuine/legit/real" trading/investment platform
//   2. Boast profits ("I made X", "I earned X", "I withdrew X")
//   3. Reference a manager/account manager/broker who "helped" them
//   4. Promote forex/crypto trading signals/bots
//   5. Ask others to reach out to their contact / share a handle
//   6. Use urgency + promise language ("limited slots", "guaranteed profit")
//
// Strategy: scored detection — 2+ signals = auto-delete+ban, 1 = warn+delete.

const TRADING_SPAM_SIGNALS = [
    // Platform claims
    { weight: 2, pattern: /\b(genuine|legit|legitimate|trusted?|verified|real)\s+(trading|investment|crypto|forex)\s*(platform|site|company|broker|firm|system|bot)\b/i },
    { weight: 2, pattern: /\b(trading|investment)\s*(platform|company|firm)\b.{0,60}(legit|genuine|real|trusted?|verified)\b/i },
    { weight: 2, pattern: /\bplatform\s*(is\s*)?(legit|genuine|real|trusted?|100%)\b/i },

    // Profit claims (the "I made X" pattern)
    { weight: 2, pattern: /\bi\s*(have\s*)?(made|earned|received|withdrawn?|profit(t?ed)?|got)\s*\$?[\d,.]+k?\s*(profit|dollar|usd|usdt|btc|ckb)?\b/i },
    { weight: 2, pattern: /\b(made|earned|profit(t?ed)?)\s*(over\s*)?\$?[\d,.]+\s*k?\b/i },
    { weight: 2, pattern: /\bwithdraw[ni]?\b.{0,40}\b(profit|earning|fund|money|usd|usdt)\b/i },
    { weight: 1, pattern: /\b(amazing|incredible|unbelievable)\s*(profit|return|earning|result)\b/i },

    // Manager / account manager references
    { weight: 3, pattern: /\b(account\s*manager|trade\s*manager|investment\s*manager|crypto\s*manager|my\s*manager|expert\s*manager)\b/i },
    { weight: 2, pattern: /\bmanager\b.{0,80}\b(contact|reach|telegram|whatsapp|signal|dm)\b/i },
    { weight: 2, pattern: /\b(contact|reach|message|dm)\b.{0,40}\bmanager\b/i },
    { weight: 2, pattern: /\b(his|her|their|the)\s*manager\b.{0,60}(helped?|assisted?|guid(e|ed)|work(ed)?)\b/i },

    // Forex/signal/bot promo
    { weight: 2, pattern: /\b(forex|binary\s*option|crypto\s*signal|trading\s*signal|trade\s*signal|trading\s*bot)\b/i },
    { weight: 2, pattern: /\bsignal\s*(provider|group|channel)\b/i },
    { weight: 1, pattern: /\b(passive\s*income|financial\s*freedom)\b.{0,60}(crypto|trade|invest|platform)\b/i },

    // Referral / share contact
    { weight: 2, pattern: /\b(his|her|their)\s*(telegram|whatsapp|signal|contact|handle|username|ig|instagram)\b.{0,40}(is|@)/i },
    { weight: 2, pattern: /\byou\s*can\s*(contact|reach|message|dm)\b.{0,60}(manager|expert|trader|investor|broker)\b/i },
    { weight: 2, pattern: /\bi\s*(can\s*)?(recommend|introduce|refer)\b.{0,60}(manager|expert|trader|platform)\b/i },

    // Urgency / guarantee language
    { weight: 1, pattern: /\b(guaranteed?\s*profit|100%\s*(safe|legit|profit)|risk[\s-]?free\s*(trade|invest|profit))\b/i },
    { weight: 1, pattern: /\blimited\s*(slot|space|spot|offer|time)\b.{0,60}(invest|trade|earn|profit)\b/i },
    { weight: 1, pattern: /\b(double|triple|10x|100x)\s*(your\s*)?(money|investment|profit|fund|capital)\b/i },

    // Recovery scams (often follow investment scams)
    { weight: 3, pattern: /\b(recovery\s*(expert|specialist|company|service|agent)|fund\s*recovery|chargeback\s*expert|hack\s*recovery)\b/i },
    { weight: 2, pattern: /\b(lost?\s*fund|lost?\s*crypto|lost?\s*bitcoin|scam\s*victim)\b.{0,60}(recover|help|contact|reach)\b/i },

    // Min-invest anchoring
    { weight: 1, pattern: /\bminimum\s*(investment|deposit|trade)\s*(of\s*)?\$?[\d,]+\b/i },
    { weight: 1, pattern: /\bstart\s*(with\s*)?\$?[\d,]+\b.{0,40}(profit|earn|trade|invest)\b/i },
];

// Sum weights of matching signals. Returns { score, matchedSignals }
function tradingSpamScore(text) {
    if (!text) return { score: 0, matchedSignals: [] };
    const matched = [];
    let score = 0;
    for (const sig of TRADING_SPAM_SIGNALS) {
        if (sig.pattern.test(text)) {
            matched.push(sig.pattern.toString().slice(1, 60) + '…');
            score += sig.weight;
        }
    }
    return { score, matchedSignals: matched };
}

// Thresholds
const TRADING_SPAM_BAN_SCORE    = 3;  // ≥3 → immediate delete+ban
const TRADING_SPAM_WARN_SCORE   = 1;  // ≥1 → warn+delete

// ─── Honeypot account detection ───────────────────────────────────────────────
//
// "Porn/OnlyFans bait" accounts follow a very consistent pattern:
//   - Female-presenting name (often generic: Sophia, Emma, Lily, etc.)
//   - Profile photo is an attractive woman (often semi-explicit thumbnail)
//   - Join group → immediately react ❤️ / 😍 / 🔥 to multiple messages
//   - Bio contains: link (t.me, onlyfans.com, linktr.ee, etc.) or emoji spam
//   - Never actually post a message — pure reaction-spam to get profile clicks
//   - Account is very new (no message history, no username or generic username)
//
// Telegram API limitations:
//   - Bots CAN receive message_reaction events (requires allowed_updates)
//   - Bots CAN call getChatMember to inspect a user
//   - Bots CANNOT read user bios directly (only via getChat for the group)
//   - Profile photo check: we use the same pHash as mod-impersonation check
//     but look for "sexually suggestive" indicators differently — we instead
//     use a reaction-rate heuristic: if a new member reacts to N messages
//     within M seconds of joining without posting anything, that's the tell.

const HONEYPOT_REACTION_EMOJIS = new Set(['❤️','😍','🔥','💋','💕','💞','😘','🥰','💯','👙']);
const HONEYPOT_REACTION_WINDOW_MS = 5 * 60 * 1000;  // 5 minutes
const HONEYPOT_REACTION_THRESHOLD  = 3;              // 3+ reactions in window = ban

// Generic "female bait" names — not exhaustive but catches the bulk
const HONEYPOT_NAME_PATTERNS = [
    /^(sophia|emma|olivia|ava|isabella|mia|luna|lily|grace|chloe|ella|zoe|aria|nora|scarlett|layla|riley|aurora|violet|stella|hannah|addison|natalie|brooklyn|leah|savannah|audrey|claire|skylar|lucy|anna|paisley|everly|ruby|maya|ariana|elena|jennifer|jessica|ashley|amanda|melissa|sarah|rachel|linda|barbara|margaret|patricia|sandra|dorothy|betty|ruth|deborah|carol|amy|angela|melissa|brenda|stephanie|virginia|kathleen|pamela|martha|diane|alice|julie|joyce|victoria|frances|kelly|joan|carmen|rose|crystal|amber|miranda|vanessa|diana|amanda|tiffany|cynthia|dawn|teresa|danielle|tammy|roxanne|ivy|jade|faith|hope|summer|autumn|sierra|sandy|sandy|cindy|candy|candi|bambi|destiny|heaven|angel|cherry|honey|sugar|princess|queen|sexy|hottie|cutie)\b/i,
];

// Reaction tracker: userId → { joinTs, reactionCount, reactionMsgIds }
const reactionTracker = new Map();

function isHoneypotName(name) {
    if (!name) return false;
    const norm = name.trim().toLowerCase();
    // Remove trailing digits/emoji to get base name
    const base = norm.replace(/[\d\s_.\-!?❤️💋😍🔥]+$/, '').trim();
    return HONEYPOT_NAME_PATTERNS.some(p => p.test(base));
}

async function handleReaction(update) {
    const rx = update.message_reaction;
    if (!rx) return;
    const grp = getGroup(rx.chat.id);
    if (!grp) return;

    const user = rx.user;
    if (!user || confirmedMods.has(user.id)) return;

    const newReactions = rx.new_reaction || [];
    const hasHoneypotEmoji = newReactions.some(r => HONEYPOT_REACTION_EMOJIS.has(r.emoji || ''));
    if (!hasHoneypotEmoji) return;

    logEvent(grp, 'reaction', {
        userId:      user.id,
        username:    user.username || null,
        name:        [user.first_name, user.last_name].filter(Boolean).join(' '),
        emojis:      newReactions.map(r => r.emoji),
        targetMsgId: rx.message_id,
        hourUTC:     new Date().getUTCHours(),
    });

    const now = Date.now();
    let tracker = reactionTracker.get(user.id);
    if (!tracker) {
        tracker = { firstReactionTs: now, reactionCount: 0, msgIds: new Set() };
        reactionTracker.set(user.id, tracker);
    }
    if (now - tracker.firstReactionTs > HONEYPOT_REACTION_WINDOW_MS) {
        tracker.firstReactionTs = now;
        tracker.reactionCount = 0;
        tracker.msgIds.clear();
    }
    tracker.msgIds.add(rx.message_id);
    tracker.reactionCount = tracker.msgIds.size;

    const name     = [user.first_name, user.last_name].filter(Boolean).join(' ');
    const nameFlag = isHoneypotName(name);
    log('INFO', `[${grp.name}] Reaction tracked: ${user.id} (${name}) count=${tracker.reactionCount} nameFlag=${nameFlag}`);

    if (tracker.reactionCount >= HONEYPOT_REACTION_THRESHOLD || (tracker.reactionCount >= 2 && nameFlag)) {
        const reason = `Honeypot account: ${tracker.reactionCount} ❤️-type reactions in ${Math.round((now - tracker.firstReactionTs)/1000)}s` +
                       (nameFlag ? `, suspicious name "${name}"` : '');
        log('ALERT', `[${grp.name}] Honeypot detected: ${user.id} (@${user.username}) — ${reason}`);
        reactionTracker.delete(user.id);

        if (grp.dryRun) {
            log('DRY-RUN', `[${grp.name}] Would ban honeypot ${user.id}`, { reason });
            appendBanLog(grp, { userId: user.id, username: user.username, reason, trigger: 'honeypot-reaction', dry_run: true });
            return;
        }
        try {
            await tgApi('banChatMember', { chat_id: grp.id, user_id: user.id });
            const alert =
                `🍯 *Honeypot account banned* (${grp.name})\n\n` +
                `👤 ${user.username ? '@' + user.username : name} (ID: \`${user.id}\`)\n` +
                `📋 ${reason}\n` +
                `🤖 Trigger: honeypot-reaction`;
            await tgApi('sendMessage', { chat_id: grp.alertChat, text: alert, parse_mode: 'Markdown' });
            appendBanLog(grp, { userId: user.id, username: user.username, reason, trigger: 'honeypot-reaction' });
            log('BAN', `[${grp.name}] Banned honeypot ${user.id}`, { reason });
        } catch (e) {
            log('ERROR', 'Honeypot ban failed', { userId: user.id, err: e.message });
        }
    }
}
const modPhotoHashes = new Map();  // userId → BigInt hash
const warnings       = new Map();  // userId → warn count
const confirmedMods  = new Set(MODS.map(m => m.user_id));
let   lastUpdateId   = 0;

// ─── Member baseline (established members — exempt from join scoring) ─────────
// Loaded from data/<groupId>/member-baseline.json on startup + periodically refreshed.
// Users in this set joined before the bot — we won't penalise them for join signals.
const memberBaselines = {}; // groupId → Set<userId>

function loadMemberBaseline(grp) {
    const baselineFile = path.join(grp.dataDir, 'member-baseline.json');
    if (!fs.existsSync(baselineFile)) {
        memberBaselines[grp.id] = new Set();
        return;
    }
    try {
        const data = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
        memberBaselines[grp.id] = new Set(Object.keys(data).map(Number));
        log('INFO', `[${grp.name}] Loaded member baseline: ${memberBaselines[grp.id].size} established users`);
    } catch (e) {
        memberBaselines[grp.id] = new Set();
        log('WARN', `[${grp.name}] Failed to load member baseline`, { err: e.message });
    }
}

function isEstablishedMember(grp, userId) {
    return memberBaselines[grp.id]?.has(userId) || confirmedMods.has(userId);
}

function addToBaseline(grp, userId, username, name) {
    // Add newly seen active users to baseline after they've been in group 24h without issues
    const baselineFile = path.join(grp.dataDir, 'member-baseline.json');
    let data = {};
    if (fs.existsSync(baselineFile)) {
        try { data = JSON.parse(fs.readFileSync(baselineFile, 'utf8')); } catch {}
    }
    if (!data[userId]) {
        data[userId] = { id: userId, username, name, role: 'member', seeded_at: new Date().toISOString(), source: 'graduated' };
        try { fs.writeFileSync(baselineFile, JSON.stringify(data, null, 2)); } catch {}
        memberBaselines[grp.id]?.add(userId);
    }
}

// ─── Logging ─────────────────────────────────────────────────────────────────

function log(level, msg, data) {
    const ts = new Date().toISOString();
    const extra = data ? ' ' + JSON.stringify(data) : '';
    console.log(`[${ts}] [${level}] ${msg}${extra}`);
}

function appendBanLog(grp, entry) {
    const p = banlogPath(grp);
    let banLog = [];
    if (fs.existsSync(p)) {
        try { banLog = JSON.parse(fs.readFileSync(p, 'utf8')); } catch {}
    }
    banLog.push({ ...entry, ts: new Date().toISOString(), group: grp.name });
    fs.writeFileSync(p, JSON.stringify(banLog, null, 2));
}

/**
 * Structured event log — one JSON line per event, per group.
 * Raw data for pattern analysis. Types:
 *   join            member joined
 *   leave           member left
 *   message         any message
 *   reaction        emoji reaction
 *   forward         forwarded message
 *   profile_change  username or display name changed
 *   detection       flagged event
 *   ban             ban executed
 */
function logEvent(grp, type, data) {
    const entry = { ts: Date.now(), iso: new Date().toISOString(), type, group: grp.name, ...data };
    try {
        fs.appendFileSync(eventlogPath(grp), JSON.stringify(entry) + '\n');
    } catch (e) {
        log('WARN', 'logEvent write failed', { err: e.message });
    }
}

// ─── Learn mode ───────────────────────────────────────────────────────────────
// Tracks bot predictions vs actual admin actions for threshold calibration.
// After 2 weeks: run calibrate.js to get precision/recall per detector.

/**
 * Log a bot prediction (would_ban / would_delete / would_restrict).
 * Called every time the bot decides to take action, whether dry_run or not.
 */
function logPrediction(grp, userId, username, trigger, score, action, reasons) {
    if (!LEARN_MODE) return;
    const entry = {
        ts:        Date.now(),
        iso:       new Date().toISOString(),
        userId,
        username:  username || null,
        trigger,
        score,
        action,       // 'ban' | 'restrict' | 'delete' | 'warn'
        reasons,
        outcome:   null,  // filled in later when/if admin confirms
        matched:   false,
    };
    try {
        fs.appendFileSync(predictionsPath(grp), JSON.stringify(entry) + '\n');
    } catch (e) {
        log('WARN', 'logPrediction write failed', { err: e.message });
    }
}

/**
 * Log an actual admin action observed in the group.
 * Called when we see a chat_member update where `from` is a human admin (not the bot).
 * Cross-references pending predictions and marks them as TRUE_POSITIVE or FALSE_NEGATIVE.
 */
function logAdminAction(grp, actorId, actorUsername, targetUserId, targetUsername, action, reason) {
    if (!LEARN_MODE) return;
    const iso = new Date().toISOString();
    const entry = {
        ts:              Date.now(),
        iso,
        actorId,
        actorUsername:   actorUsername || null,
        targetUserId,
        targetUsername:  targetUsername || null,
        action,          // 'ban' | 'kick' | 'restrict' | 'unban'
        reason:          reason || null,
    };
    try {
        fs.appendFileSync(adminActionsPath(grp), JSON.stringify(entry) + '\n');
    } catch (e) {
        log('WARN', 'logAdminAction write failed', { err: e.message });
    }

    // Cross-reference: was this user in our pending predictions?
    reconcilePrediction(grp, targetUserId, action, iso);
}

/**
 * Reconcile a prediction against an admin action.
 * Rewrites the prediction line with outcome = TRUE_POSITIVE.
 * If no prediction exists, logs a FALSE_NEGATIVE (admin caught something we missed).
 */
function reconcilePrediction(grp, userId, adminAction, iso) {
    const p = predictionsPath(grp);
    if (!fs.existsSync(p)) {
        // No predictions yet — log as false negative
        logFalseNegative(grp, userId, adminAction, iso);
        return;
    }

    const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
    let matched = false;

    const updated = lines.map(line => {
        try {
            const pred = JSON.parse(line);
            if (pred.userId === userId && pred.outcome === null) {
                matched = true;
                pred.outcome = 'TRUE_POSITIVE';
                pred.matched = true;
                pred.confirmedBy = adminAction;
                pred.confirmedAt = iso;
            }
            return JSON.stringify(pred);
        } catch { return line; }
    });

    fs.writeFileSync(p, updated.join('\n') + '\n');

    if (!matched) {
        logFalseNegative(grp, userId, adminAction, iso);
    }
}

function logFalseNegative(grp, userId, adminAction, iso) {
    // Admin acted on someone we never flagged → false negative
    const entry = {
        ts:       Date.now(),
        iso,
        userId,
        trigger:  'missed',
        outcome:  'FALSE_NEGATIVE',
        matched:  false,
        adminAction,
    };
    try {
        fs.appendFileSync(predictionsPath(grp), JSON.stringify(entry) + '\n');
    } catch {}
    log('LEARN', `FALSE_NEGATIVE: Admin actioned user ${userId} (${adminAction}) that bot didn't flag`);
}

/**
 * Periodically mark unmatched predictions older than 48h as FALSE_POSITIVE
 * (bot flagged, but no admin action followed → likely wrong).
 */
function agePredictions(grp) {
    if (!LEARN_MODE) return;
    const p = predictionsPath(grp);
    if (!fs.existsSync(p)) return;

    const cutoff = Date.now() - 48 * 3600 * 1000;
    const lines  = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
    let changed  = false;

    const updated = lines.map(line => {
        try {
            const pred = JSON.parse(line);
            if (pred.outcome === null && pred.ts < cutoff) {
                pred.outcome  = 'FALSE_POSITIVE';
                pred.agedOut  = true;
                changed = true;
            }
            return JSON.stringify(pred);
        } catch { return line; }
    });

    if (changed) fs.writeFileSync(p, updated.join('\n') + '\n');
}

// ─── HTTP helper ───────────────────────────────────────────────────────────────

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

async function banUser(grp, userId, username, reason, trigger, score = 0, reasons = []) {
    // Always log prediction in learn mode (regardless of dry_run)
    logPrediction(grp, userId, username, trigger, score, 'ban', reasons);

    if (grp.dryRun) {
        log('DRY-RUN', `[${grp.name}] Would ban ${userId} (@${username})`, { reason, trigger });
        appendBanLog(grp, { userId, username, reason, trigger, dry_run: true });
        logEvent(grp, 'ban', { userId, username, trigger, dry_run: true });
        return;
    }
    try {
        await tgApi('banChatMember', { chat_id: grp.id, user_id: userId });
        log('BAN', `[${grp.name}] Banned ${userId} (@${username})`, { reason });
        appendBanLog(grp, { userId, username, reason, trigger });
        logEvent(grp, 'ban', { userId, username, trigger, dry_run: false });
        const alert =
            `🚫 *Scammer banned* (${grp.name})\n\n` +
            `👤 ${username ? '@' + username : 'no username'} (ID: \`${userId}\`)\n` +
            `📋 ${reason}\n` +
            `🤖 Trigger: ${trigger}`;
        await tgApi('sendMessage', { chat_id: grp.alertChat, text: alert, parse_mode: 'Markdown' });
    } catch (e) {
        log('ERROR', `[${grp.name}] Ban failed`, { userId, err: e.message });
    }
}

async function deleteMsg(grp, messageId, userId, trigger, score) {
    logPrediction(grp, userId, null, trigger || 'delete', score || 0, 'delete', []);
    if (grp.dryRun) { log('DRY-RUN', `[${grp.name}] Would delete message ${messageId}`); return; }
    try { await tgApi('deleteMessage', { chat_id: grp.id, message_id: messageId }); }
    catch (e) { log('WARN', 'Delete failed', { messageId, err: e.message }); }
}

async function sendMsg(chatId, text, extra = {}) {
    try { await tgApi('sendMessage', { chat_id: chatId, text, ...extra }); }
    catch (e) { log('WARN', 'Send failed', { err: e.message }); }
}

// ─── Behavioural bot detection engine ────────────────────────────────────────
//
// Scores each user across multiple behavioural signals over time.
// No single signal bans anyone — it's the combination that matters.
// This catches hidden bots that don't trigger content filters.
//
// Score thresholds (configurable in config.json under "bot_behaviour"):
//   ≥ 6 → immediate ban
//   ≥ 4 → mute + alert to mod (ban on next offence)
//   ≥ 2 → silent flag (watch closely)

const BOT_BAN_SCORE   = config.bot_behaviour?.ban_score   ?? 6;
const BOT_ALERT_SCORE = config.bot_behaviour?.alert_score ?? 4;
const BOT_FLAG_SCORE  = config.bot_behaviour?.flag_score  ?? 2;

// Per-user behavioural state
// userId → {
//   joinTs, lastMsgTs, msgCount, msgIntervals[],
//   msgHashes: Set, leaveCount, joinCount,
//   score, scoreReasons[], warned, flagged
// }
const behaviourMap = new Map();

function getBehaviour(userId) {
    if (!behaviourMap.has(userId)) {
        behaviourMap.set(userId, {
            joinTs:       null,
            lastMsgTs:    null,
            msgCount:     0,
            msgIntervals: [],   // ms between consecutive messages
            msgHashes:    new Set(),
            leaveCount:   0,
            joinCount:    0,
            score:        0,
            scoreReasons: [],
            warned:       false,
            flagged:      false,
        });
    }
    return behaviourMap.get(userId);
}

// Simple fast text fingerprint (not cryptographic — just for dupe detection)
function textFingerprint(text) {
    // Normalise whitespace, lowercase, strip URLs → short hash
    const norm = text.toLowerCase()
        .replace(/https?:\/\/\S+/g, '<url>')
        .replace(/\s+/g, ' ')
        .trim();
    // djb2-style hash
    let h = 5381;
    for (let i = 0; i < norm.length; i++) h = ((h << 5) + h) ^ norm.charCodeAt(i);
    return (h >>> 0).toString(16);
}

function addScore(beh, points, reason) {
    beh.score += points;
    beh.scoreReasons.push(`[+${points}] ${reason}`);
}

// Analyse a user's behaviour when they send a message
function scoreBehaviourOnMessage(userId, msg) {
    const beh = getBehaviour(userId);
    const now  = Date.now();
    const text = msg.text || msg.caption || '';
    const from = msg.from || {};

    // ── Signal 1: Message immediately after joining (<10s) ──
    if (beh.joinTs && (now - beh.joinTs) < 10_000 && beh.msgCount === 0) {
        addScore(beh, 3, 'Posted within 10s of joining (pre-scripted)');
    }

    // ── Signal 2: Message cadence — suspiciously regular intervals ──
    if (beh.lastMsgTs) {
        const interval = now - beh.lastMsgTs;
        beh.msgIntervals.push(interval);
        if (beh.msgIntervals.length >= 4) {
            // Check coefficient of variation: low CV = robot-regular
            const intervals = beh.msgIntervals.slice(-6);
            const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
            const cv = Math.sqrt(variance) / mean;
            if (mean < 60_000 && cv < 0.10) { // faster than 1/min, <10% variance
                addScore(beh, 3, `Robot-regular cadence: mean=${Math.round(mean/1000)}s CV=${cv.toFixed(3)}`);
            }
        }
    }
    beh.lastMsgTs = now;
    beh.msgCount++;

    // ── Signal 3: Copy-paste / identical message ──
    if (text.length > 20) {
        const fp = textFingerprint(text);
        if (beh.msgHashes.has(fp)) {
            addScore(beh, 3, 'Sent identical message again (copy-paste spam)');
        }
        beh.msgHashes.add(fp);
        // Also check for near-identical via shared fingerprints across ALL users
        // (coordinated botnet — same message from different accounts)
        if (!globalMsgFingerprints.has(fp)) {
            globalMsgFingerprints.set(fp, { count: 0, users: new Set(), firstTs: now });
        }
        const gfp = globalMsgFingerprints.get(fp);
        gfp.count++;
        gfp.users.add(userId);
        if (gfp.users.size >= 3 && (now - gfp.firstTs) < 10 * 60_000) {
            addScore(beh, 4, `Coordinated botnet: same message from ${gfp.users.size} accounts in 10min`);
        }
    }

    // ── Signal 4: Forwarded message from a channel ──
    if (msg.forward_origin || msg.forward_from || msg.forward_from_chat) {
        addScore(beh, 1, 'Message is a forward (not original content)');
        // Extra points if the forwarded channel name looks spammy
        const fwdName = msg.forward_from_chat?.title || msg.forward_from?.first_name || '';
        const { score: fwdTradingScore } = tradingSpamScore(fwdName);
        if (fwdTradingScore >= 2) {
            addScore(beh, 3, `Forwarded from suspicious channel: "${fwdName}"`);
        }
    }

    // ── Signal 5: URL-only message (no surrounding text) ──
    if (text.length > 0) {
        const urlOnly = /^https?:\/\/\S+$/.test(text.trim());
        const hasEntities = (msg.entities || []).some(e => e.type === 'url' || e.type === 'text_link');
        if (urlOnly || (hasEntities && text.trim().split(/\s+/).length <= 2)) {
            addScore(beh, 2, 'URL-only message with no context');
        }
    }

    // ── Signal 6: User metadata flags ──
    if (beh.msgCount === 1) { // only check once per user
        // No username (anonymous-ish account)
        if (!from.username) {
            addScore(beh, 1, 'No username set');
        }
        // Language code mismatch — account says non-English but name is English
        const lang = from.language_code || '';
        const name = (from.first_name || '').toLowerCase();
        const englishName = /^[a-z\s'-]+$/.test(name);
        if (englishName && lang && !lang.startsWith('en') &&
            ['ru', 'zh', 'vi', 'id', 'tr', 'ar', 'fa'].some(l => lang.startsWith(l))) {
            addScore(beh, 1, `Language mismatch: name="${name}" lang=${lang}`);
        }
        // Very new account (Telegram user IDs are roughly sequential/chronological)
        // IDs above ~7.5B were registered after ~2024, common for bot farms
        if (userId > 7_500_000_000) {
            addScore(beh, 1, `Very new account (user_id=${userId})`);
        }
    }

    return beh;
}

// Cross-group fingerprint for coordinated botnet detection
const globalMsgFingerprints = new Map(); // fp → { count, users: Set, firstTs }

// Periodically clean old fingerprints (>30min old)
setInterval(() => {
    const cutoff = Date.now() - 30 * 60_000;
    for (const [fp, data] of globalMsgFingerprints) {
        if (data.firstTs < cutoff) globalMsgFingerprints.delete(fp);
    }
    // Also clean old behaviour entries for users who left >2h ago
    for (const [uid, beh] of behaviourMap) {
        if (beh.lastMsgTs && Date.now() - beh.lastMsgTs > 2 * 60 * 60_000 && beh.score < BOT_FLAG_SCORE) {
            behaviourMap.delete(uid);
        }
    }
}, 5 * 60_000);

// Handle chat_member status changes (join/leave/kick/ban tracking)
async function handleChatMember(update) {
    const cm = update.chat_member;
    if (!cm) return;
    const grp = getGroup(cm.chat.id);
    if (!grp) return;

    const oldUser  = cm.old_chat_member?.user;
    const newUser  = cm.new_chat_member?.user;
    const user     = newUser || cm.from;
    if (!user || user.is_bot || confirmedMods.has(user.id)) return;

    const oldStatus = cm.old_chat_member?.status || 'left';
    const newStatus = cm.new_chat_member?.status  || 'left';

    const beh = getBehaviour(user.id);

    // ── Admin action detection (learn mode) ──────────────────────────────────
    // If the update was triggered BY a human admin (not the bot itself, not the user),
    // and resulted in a ban/kick/restrict → log as admin action for calibration.
    if (LEARN_MODE && cm.from && !cm.from.is_bot) {
        const actor = cm.from;
        const isOurBot = actor.id === 7138613671; // @Nervos_bot
        if (!isOurBot && actor.id !== (newUser?.id)) {
            // actor is a human doing something to newUser/user
            if (newStatus === 'kicked' || newStatus === 'banned') {
                logAdminAction(
                    grp,
                    actor.id, actor.username,
                    user.id, user.username,
                    'ban',
                    `Admin action: ${actor.username || actor.id} banned ${user.username || user.id}`
                );
                log('LEARN', `[${grp.name}] Admin ban observed: ${actor.username || actor.id} → ${user.username || user.id} (${user.id})`);
            } else if (newStatus === 'restricted') {
                logAdminAction(
                    grp,
                    actor.id, actor.username,
                    user.id, user.username,
                    'restrict',
                    null
                );
            } else if (newStatus === 'left' && oldStatus === 'member') {
                // Could be a kick (admin-initiated leave)
                if (actor.id !== user.id) {
                    logAdminAction(
                        grp,
                        actor.id, actor.username,
                        user.id, user.username,
                        'kick',
                        null
                    );
                }
            }
        }
    }

    // ── Username / display-name change detection ──────────────────────────────
    // Telegram sends a chat_member update whenever a member edits their profile
    // while inside the group. old_chat_member.user → before, new_chat_member.user → after.
    // This is the primary early-warning vector for admin impersonators:
    // they join with an innocent name, lurk, then rename to "Nervos Support" etc.
    if (oldStatus === newStatus && oldUser && newUser) {
        const oldName = [oldUser.first_name, oldUser.last_name].filter(Boolean).join(' ').trim();
        const newName = [newUser.first_name, newUser.last_name].filter(Boolean).join(' ').trim();
        const oldUN   = (oldUser.username || '').toLowerCase();
        const newUN   = (newUser.username || '').toLowerCase();

        const nameChanged = oldName !== newName;
        const unChanged   = oldUN   !== newUN;

        if (nameChanged || unChanged) {
            log('INFO', `[${grp.name}] Profile change: [${user.id}] "${oldName}"(@${oldUN}) → "${newName}"(@${newUN})`);
            logEvent(grp, 'profile_change', {
                userId:      user.id,
                oldName, newName,
                oldUsername: oldUN || null,
                newUsername: newUN || null,
                hourUTC:     new Date().getUTCHours(),
            });

            const [newFirst, ...newRest] = newName.split(' ');
            const newLast = newRest.join(' ') || null;
            const impCheck = await checkUser(user.id, newFirst, newLast, newUser.username);

            if (impCheck.suspicious) {
                const reason = `Name change to impersonate mod: "${oldName}" → "${newName}" — ${impCheck.reasons}`;
                log('ALERT', `[${grp.name}] Impersonation via rename: ${user.id}`, { oldName, newName, reasons: impCheck.reasons });
                logEvent(grp, 'detection', {
                    userId: user.id, username: newUN || null,
                    detector: 'rename-impersonation',
                    oldName, newName, reasons: impCheck.reasons,
                });
                await banUser(grp, user.id, newUser.username, reason, 'rename-impersonation');

            } else {
                const suspiciousWords = /\b(admin|mod|moderator|support|official|team|staff|dev|developer|founder|ceo|core|nervos|ckb)\b/i;
                const nameNowSuspicious = suspiciousWords.test(newName);
                const wasInnocent       = !suspiciousWords.test(oldName);

                if (nameNowSuspicious && wasInnocent) {
                    addScore(beh, 3, `Renamed to authority-sounding name: "${oldName}" → "${newName}"`);
                    await evaluateBehaviourScore(grp, user, beh);

                    const alert =
                        `🔄 *Suspicious rename detected* (${grp.name})\n\n` +
                        `👤 ${newUN ? '@' + newUN : newName} (ID: \`${user.id}\`)\n` +
                        `📛 "${oldName}" → *"${newName}"*\n` +
                        `📊 Bot score now: ${beh.score}\n` +
                        `⚠️ Name suggests authority/impersonation — watching`;
                    try {
                        await tgApi('sendMessage', { chat_id: grp.alertChat, text: alert, parse_mode: 'Markdown' });
                    } catch {}
                }

                if (unChanged) {
                    if (!beh.usernameHistory) beh.usernameHistory = [];
                    beh.usernameHistory.push({ from: oldUN, to: newUN, ts: Date.now() });
                    if (beh.usernameHistory.length >= 2) {
                        const recent = beh.usernameHistory.filter(h => Date.now() - h.ts < 60 * 60_000);
                        if (recent.length >= 2) {
                            addScore(beh, 2, `Username cycled ${recent.length}x in 1h: ${recent.map(h => h.from+'→'+h.to).join(', ')}`);
                            await evaluateBehaviourScore(grp, user, beh);
                        }
                    }
                }
            }
        }
    }

    // ── Join event ──
    if ((oldStatus === 'left' || oldStatus === 'kicked') && newStatus === 'member') {
        beh.joinCount++;
        beh.joinTs = Date.now();

        logEvent(grp, 'join', {
            userId:   user.id,
            name:     [user.first_name, user.last_name].filter(Boolean).join(' '),
            username: user.username || null,
            lang:     user.language_code || null,
            isPremium: user.is_premium || false,
            joinCount: beh.joinCount,
            hourUTC:  new Date().getUTCHours(),
        });

        // Signal: rejoining after leaving/being kicked
        // (skip for established baseline members — they may have left/rejoined legitimately)
        if (beh.joinCount > 1 && !isEstablishedMember(grp, user.id)) {
            addScore(beh, 2, `Re-joined group (join #${beh.joinCount}) — possible ban evasion`);
        }

        // Signal: joined in a burst with others (coordinated botnet)
        // (skip if user is in member baseline)
        if (!isEstablishedMember(grp, user.id)) {
            joinBurst.push({ userId: user.id, ts: Date.now() });
            // Clean old burst entries
            const burstWindow = Date.now() - 30_000; // 30 second window
            while (joinBurst.length && joinBurst[0].ts < burstWindow) joinBurst.shift();
            if (joinBurst.length >= 5) {
                const unique = new Set(joinBurst.map(j => j.userId)).size;
                addScore(beh, 3, `Mass join burst: ${unique} accounts joined within 30s`);
            }
        }

        log('INFO', `Member joined: ${user.first_name} (@${user.username}) [${user.id}] join#${beh.joinCount}`);
    }

    // ── Leave event ──
    if (newStatus === 'left' || newStatus === 'kicked') {
        beh.leaveCount++;
        const timeInGroup = beh.joinTs ? Date.now() - beh.joinTs : null;

        logEvent(grp, 'leave', {
            userId:        user.id,
            username:      user.username || null,
            timeInGroupSec: timeInGroup ? Math.round(timeInGroup / 1000) : null,
            msgCount:      beh.msgCount,
            leaveCount:    beh.leaveCount,
            botScore:      beh.score,
            hourUTC:       new Date().getUTCHours(),
        });

        // Signal: left very quickly without posting
        if (timeInGroup !== null && timeInGroup < 3 * 60_000 && beh.msgCount === 0) {
            addScore(beh, 2, `Left without posting after ${Math.round(timeInGroup/1000)}s — lurk-bot`);
        }

        // Signal: repeated join/leave cycle
        if (beh.joinCount >= 2 && beh.leaveCount >= 2) {
            addScore(beh, 3, `Join/leave cycling: ${beh.joinCount} joins, ${beh.leaveCount} leaves`);
        }

        log('INFO', `Member left: ${user.first_name} (@${user.username}) [${user.id}] score=${beh.score}`);
    }

    // Act on accumulated score
    await evaluateBehaviourScore(grp, user, beh);
}

const joinBurst = []; // rolling window of recent joins

async function evaluateBehaviourScore(grp, user, beh) {
    if (beh.warned && beh.score < BOT_BAN_SCORE) return;

    const name     = [user.first_name, user.last_name].filter(Boolean).join(' ');
    const username = user.username;

    if (beh.score >= BOT_BAN_SCORE && !beh.flagged) {
        beh.flagged = true;
        const reason = `Bot behaviour score ${beh.score}/6+:\n${beh.scoreReasons.join('\n')}`;
        log('ALERT', `[${grp.name}] Bot detected: ${user.id} (${name}) score=${beh.score}`, { reasons: beh.scoreReasons });

        if (grp.dryRun) {
            log('DRY-RUN', `[${grp.name}] Would ban bot ${user.id}`, { reason });
            appendBanLog(grp, { userId: user.id, username, reason, trigger: 'bot-behaviour', dry_run: true });
            return;
        }
        try {
            await tgApi('banChatMember', { chat_id: grp.id, user_id: user.id });
            const alert =
                `🤖 *Bot account banned* (${grp.name})\n\n` +
                `👤 ${username ? '@' + username : name} (ID: \`${user.id}\`)\n` +
                `📊 Score: ${beh.score}\n` +
                `📋 ${beh.scoreReasons.slice(0, 4).join('\n')}\n` +
                `🤖 Trigger: bot-behaviour`;
            await tgApi('sendMessage', { chat_id: grp.alertChat, text: alert, parse_mode: 'Markdown' });
            appendBanLog(grp, { userId: user.id, username, reason, score: beh.score, trigger: 'bot-behaviour' });
        } catch (e) {
            log('ERROR', `[${grp.name}] Bot ban failed`, { userId: user.id, err: e.message });
        }

    } else if (beh.score >= BOT_ALERT_SCORE && !beh.warned) {
        beh.warned = true;
        const alert =
            `⚠️ *Suspected bot — watching* (${grp.name})\n\n` +
            `👤 ${username ? '@' + username : name} (ID: \`${user.id}\`)\n` +
            `📊 Score: ${beh.score} (ban threshold: ${BOT_BAN_SCORE})\n` +
            `📋 ${beh.scoreReasons.join('\n')}`;
        log('WARN', `[${grp.name}] Bot watch: ${user.id} score=${beh.score}`, { reasons: beh.scoreReasons });
        try {
            await tgApi('sendMessage', { chat_id: grp.alertChat, text: alert, parse_mode: 'Markdown' });
        } catch {}
    } else if (beh.score >= BOT_FLAG_SCORE) {
        log('INFO', `[${grp.name}] Bot flagged (silent): ${user.id} score=${beh.score}`, { reasons: beh.scoreReasons });
    }
}

// ─── Update handlers ──────────────────────────────────────────────────────────

async function handleNewMembers(grp, msg) {
    for (const member of (msg.new_chat_members || [])) {
        if (member.is_bot) continue;
        const { id: userId, username, first_name: first, last_name: last } = member;
        log('INFO', `[${grp.name}] New member: ${first} ${last || ''} (@${username}) [${userId}]`);
        const result = await checkUser(userId, first, last, username);
        if (result.suspicious) {
            await deleteMsg(grp, msg.message_id);
            await banUser(grp, userId, username,
                `Fake mod on join: ${result.reasons}`, 'join-check');
        }
    }
}

async function handleMessage(grp, msg) {
    const from = msg.from;
    if (!from || from.is_bot) return;
    const { id: userId, username, first_name: first, last_name: last } = from;
    const text  = msg.text || msg.caption || '';
    const msgId = msg.message_id;

    if (confirmedMods.has(userId)) return;
    if (!text) return;

    // ── Structured event log (every non-mod message) ──
    const isForward  = !!(msg.forward_origin || msg.forward_from || msg.forward_from_chat);
    const hasUrl     = (msg.entities || []).some(e => e.type === 'url' || e.type === 'text_link');
    const isReply    = !!msg.reply_to_message;
    const msgHour    = new Date().getUTCHours();
    const timeInGrp  = behaviourMap.get(userId)?.joinTs
                       ? Math.round((Date.now() - behaviourMap.get(userId).joinTs) / 1000)
                       : null;
    logEvent(grp, 'message', {
        userId,
        username:     username || null,
        lang:         from.language_code || null,
        msgLen:       text.length,
        hasUrl,
        isForward,
        isReply,
        isCaption:    !!msg.caption,
        hourUTC:      msgHour,
        secSinceJoin: timeInGrp,
        fwdChatTitle: msg.forward_from_chat?.title || null,
        fwdChatType:  msg.forward_from_chat?.type  || null,
        // Don't log message content here — that's in antiscam.log on ALERT
    });

    // ── Behavioural scoring (runs on every message regardless of content) ──
    const beh = scoreBehaviourOnMessage(userId, msg);
    await evaluateBehaviourScore(grp, from, beh);

    const baiting  = isDmBait(text);
    const claiming = claimsAdmin(text);
    const { score: tradingScore, matchedSignals } = tradingSpamScore(text);
    const isTrading = tradingScore >= TRADING_SPAM_WARN_SCORE;

    if (!baiting && !claiming && !isTrading) return;

    log('ALERT', `Suspicious message from ${userId}`, {
        text: text.slice(0, 120),
        baiting, claiming, tradingScore,
    });
    logEvent(grp, 'detection', {
        userId, username: username || null,
        detector: baiting ? 'dm-bait' : claiming ? 'admin-claim' : 'trading-spam',
        tradingScore, baiting, claiming,
        textSnippet: text.slice(0, 100),
    });

    // ── Trading spam path (independent of user identity check) ──
    if (isTrading && !baiting && !claiming) {
        if (tradingScore >= TRADING_SPAM_BAN_SCORE) {
            // High-confidence spam — delete and ban immediately
            await deleteMsg(grp, msgId);
            const reason = `Trading/investment spam (score=${tradingScore}): ${matchedSignals.slice(0,3).join(' | ')}`;
            await banUser(grp, userId, username, reason, 'trading-spam');
        } else {
            // Low-confidence — delete + warn, track for repeat offences
            await deleteMsg(grp, msgId);
            const warnCount = (warnings.get(userId) || 0) + 1;
            warnings.set(userId, warnCount);
            if (warnCount >= 2) {
                await banUser(grp, userId, username,
                    `Repeated trading spam after ${warnCount - 1} warning(s)`, 'trading-spam-repeat');
            } else {
                await sendMsg(grp.id,
                    `⚠️ ${username ? '@' + username : first} — promoting trading platforms or investment schemes is not allowed here. Message deleted. Next offence = ban.`);
            }
        }
        return;
    }

    const userCheck = await checkUser(userId, first, last, username);

    // ── Combined path (DM-bait / admin-claim + optional trading) ──
    if (claiming || userCheck.suspicious || tradingScore >= TRADING_SPAM_BAN_SCORE) {
        // High confidence — immediate ban
        await deleteMsg(grp, msgId);
        const reasons = [
            baiting    ? 'DM-baiting' : null,
            claiming   ? 'Claims to be admin' : null,
            userCheck.suspicious ? userCheck.reasons : null,
            isTrading  ? `Trading spam (score=${tradingScore})` : null,
        ].filter(Boolean).join('; ');
        await banUser(grp, userId, username, reasons, 'message-check');

    } else if (baiting && WARN_FIRST) {
        const warnCount = (warnings.get(userId) || 0) + 1;
        warnings.set(userId, warnCount);
        await deleteMsg(grp, msgId);
        if (warnCount >= 2) {
            await banUser(grp, userId, username,
                `Repeated DM-baiting after ${warnCount - 1} warning(s)`, 'warn-threshold');
        } else {
            await sendMsg(grp.id,
                `⚠️ ${username ? '@' + username : first} — asking people to DM you is not allowed here. ` +
                `Warning 1/2. Next offence = ban.`);
        }
    } else {
        await deleteMsg(grp, msgId);
        await banUser(grp, userId, username, 'DM-baiting message', 'message-check');
    }
}

async function handleCommand(msg) {
    if (!confirmedMods.has(msg.from.id)) return;
    const text = msg.text || '';
    const chatId = String(msg.chat.id);

    if (text.startsWith('/bans')) {
        const n = parseInt(text.split(' ')[1] || '5');
        // Merge ban logs from all groups
        let banLog = [];
        for (const grp of GROUPS) {
            const p = banlogPath(grp);
            if (fs.existsSync(p)) {
                try {
                    const entries = JSON.parse(fs.readFileSync(p, 'utf8'));
                    banLog.push(...entries);
                } catch {}
            }
        }
        banLog.sort((a, b) => new Date(b.ts) - new Date(a.ts));
        const recent = banLog.slice(0, n);
        if (!recent.length) return sendMsg(chatId, '📋 No bans logged yet.');
        const lines = recent.map((b, i) =>
            `${i+1}. @${b.username || 'n/a'} (${b.userId}) [${b.group || '?'}]\n   ${b.reason}\n   ${b.ts}`
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

    if (text.startsWith('/testscan')) {
        // Usage: /testscan <message text to analyse>
        const sample = text.replace(/^\/testscan\s*/, '').trim();
        if (!sample) return sendMsg(chatId, 'Usage: /testscan <text to analyse>');
        const { score, matchedSignals } = tradingSpamScore(sample);
        const dmBait  = isDmBait(sample);
        const isAdmin = claimsAdmin(sample);
        const verdict = score >= TRADING_SPAM_BAN_SCORE ? '🚫 BAN' :
                        score >= TRADING_SPAM_WARN_SCORE ? '⚠️ WARN' : '✅ CLEAN';
        const lines = [
            `*Scan result:* ${verdict}`,
            `Trading score: ${score} (ban≥${TRADING_SPAM_BAN_SCORE}, warn≥${TRADING_SPAM_WARN_SCORE})`,
            dmBait  ? '🔴 DM-bait detected' : '✅ No DM-bait',
            isAdmin ? '🔴 Admin claim detected' : '✅ No admin claim',
        ];
        if (matchedSignals.length)
            lines.push(`\nMatched signals:\n• ${matchedSignals.join('\n• ')}`);
        return sendMsg(chatId, lines.join('\n'), { parse_mode: 'Markdown' });
    }

    if (text.startsWith('/botstats')) {
        // Show top suspicious users by behaviour score
        const entries = [...behaviourMap.entries()]
            .filter(([, b]) => b.score >= BOT_FLAG_SCORE)
            .sort(([, a], [, b]) => b.score - a.score)
            .slice(0, 10);
        if (!entries.length)
            return sendMsg(chatId, '📊 No flagged users at the moment.');
        const lines = entries.map(([uid, b], i) => {
            const age = b.joinTs ? `${Math.round((Date.now()-b.joinTs)/60000)}min ago` : 'unknown';
            return `${i+1}. ID \`${uid}\` score=${b.score} msgs=${b.msgCount} joined=${age}\n   ${b.scoreReasons.slice(0,2).join(' | ')}`;
        });
        return sendMsg(chatId,
            `🤖 *Flagged users (score≥${BOT_FLAG_SCORE}):*\n\n${lines.join('\n\n')}`,
            { parse_mode: 'Markdown' });
    }

    if (text.startsWith('/checkscore')) {
        // /checkscore @username or reply to a message
        const replied = msg.reply_to_message?.from;
        if (replied) {
            const beh = getBehaviour(replied.id);
            const lines = [
                `*User:* ${replied.first_name} (@${replied.username || 'none'}) ID: \`${replied.id}\``,
                `*Bot score:* ${beh.score}`,
                `*Messages:* ${beh.msgCount}`,
                `*Join/leave:* ${beh.joinCount}/${beh.leaveCount}`,
                beh.scoreReasons.length ? `\n*Reasons:*\n${beh.scoreReasons.join('\n')}` : '✅ No flags',
            ];
            return sendMsg(chatId, lines.join('\n'), { parse_mode: 'Markdown' });
        }
        return sendMsg(chatId, 'Reply to a message to check that user\'s bot score.');
    }
}

// ─── Polling loop ─────────────────────────────────────────────────────────────

async function poll() {
    try {
        const updates = await tgApi('getUpdates', {
            offset: lastUpdateId + 1,
            timeout: 30,
            allowed_updates: ['message', 'chat_member', 'message_reaction'],
        });

        for (const update of (updates || [])) {
            lastUpdateId = update.update_id;

            // ── Reaction events (honeypot detection) ──
            if (update.message_reaction) {
                await handleReaction(update);
                continue;
            }

            // ── Chat member status changes (join/leave tracking) ──
            if (update.chat_member) {
                await handleChatMember(update);
                continue;
            }

            const msg = update.message;
            if (!msg) continue;

            const chatId = String(msg.chat.id);
            const grp    = getGroup(chatId);

            if (!grp) {
                // Not one of our monitored groups — only handle private /commands from mods
                if (msg.text && msg.text.startsWith('/') && confirmedMods.has(msg.from?.id)) {
                    await handleCommand(msg);
                }
                continue;
            }

            if (msg.new_chat_members) {
                await handleNewMembers(grp, msg);
            } else if (msg.text || msg.caption) {
                if (msg.text && msg.text.startsWith('/')) {
                    await handleCommand(msg);
                } else {
                    await handleMessage(grp, msg);
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
    for (const grp of GROUPS) {
        log('INFO', `Monitoring: ${grp.name} (${grp.id}) → alerts → ${grp.alertChat} [dry_run: ${grp.dryRun}]`);
    }
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

    // Load mod photo hashes + member baselines
    await loadModHashes();
    for (const grp of Object.values(groups)) loadMemberBaseline(grp);

    // Refresh hashes every 6 hours + age out stale predictions
    setInterval(async () => {
        log('INFO', 'Scheduled photo hash refresh + prediction aging...');
        modPhotoHashes.clear();
        await loadModHashes();
        if (LEARN_MODE) {
            for (const grp of Object.values(groups)) agePredictions(grp);
        }
        // Graduate clean users to member baseline (in group 24h+ with score < 5)
        for (const grp of Object.values(groups)) {
            const now = Date.now();
            for (const [uid, beh] of behaviourMap.entries()) {
                if (beh.joinTs && (now - beh.joinTs) > 24 * 3600 * 1000 && beh.score < 5) {
                    addToBaseline(grp, uid, beh.username || null, beh.name || null);
                }
            }
        }
    }, 6 * 60 * 60 * 1000);

    log('INFO', '✅ Polling for updates...');
    const anyDryRun = GROUPS.some(g => g.dryRun);
    if (anyDryRun) log('INFO', '⚠️  DRY-RUN MODE (some or all groups) — logging only, no bans or deletes');

    // Long-polling loop
    while (true) {
        await poll();
    }
}

main().catch(e => {
    log('ERROR', 'Fatal', { err: e.message });
    process.exit(1);
});
