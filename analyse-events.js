#!/usr/bin/env node
/**
 * analyse-events.js — Pattern analysis over event-log.jsonl
 *
 * Run manually: node analyse-events.js
 * Or called from heartbeat to produce a summary.
 *
 * Outputs:
 *   - Join/leave stats (who lurks, who bounces)
 *   - Message timing patterns (cadence, hour distribution)
 *   - Reaction hot-users
 *   - Bot score leaderboard
 *   - Forwarded message sources
 *   - Recent detections / bans
 *   - Recommendations for threshold tuning
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// Usage: node analyse-events.js [hours] [group-name-or-id]
const WINDOW_H  = parseInt(process.argv[2] || '12');
const GROUP_ARG = (process.argv[3] || '').toLowerCase();
const cutoffTs  = Date.now() - WINDOW_H * 60 * 60 * 1000;

const DATA_DIR = path.join(__dirname, 'data');

// Find event log(s) to analyse
function findEventLogs() {
    if (!fs.existsSync(DATA_DIR)) return [];
    const groups = fs.readdirSync(DATA_DIR).filter(d =>
        fs.statSync(path.join(DATA_DIR, d)).isDirectory()
    );
    return groups
        .filter(d => !GROUP_ARG || d.includes(GROUP_ARG))
        .map(d => ({
            dir: d,
            logPath: path.join(DATA_DIR, d, 'event-log.jsonl'),
            banPath: path.join(DATA_DIR, d, 'ban-log.json'),
        }))
        .filter(g => fs.existsSync(g.logPath));
}

const groupDirs = findEventLogs();

if (!groupDirs.length) {
    console.log(`No event logs found under ${DATA_DIR}`);
    console.log('Make sure the bot has admin rights and has been running a while.');
    console.log('Usage: node analyse-events.js <hours> [group-name-or-partial-id]');
    process.exit(0);
}

// Load + merge events across selected groups (tagged by group name in log)
let events = [];
for (const g of groupDirs) {
    const lines = fs.readFileSync(g.logPath, 'utf8').split('\n').filter(Boolean);
    const parsed = lines.map(l => { try { return JSON.parse(l); } catch { return null; } })
                        .filter(Boolean)
                        .filter(e => e.ts >= cutoffTs);
    events.push(...parsed);
}

events.sort((a, b) => a.ts - b.ts);

// ── Helpers ──
const byType = type => events.filter(e => e.type === type);
const countBy = (arr, key) => {
    const m = {};
    arr.forEach(e => { const v = e[key]; m[v] = (m[v] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
};
const pct = (n, total) => total ? `${Math.round(100 * n / total)}%` : '0%';

// ── Analyse ──
const joins    = byType('join');
const leaves   = byType('leave');
const messages = byType('message');
const reactions= byType('reaction');
const renames  = byType('profile_change');
const detections=byType('detection');
const bans     = byType('ban');

// Join/leave lurkers: left within 3 min without posting
const lurkers = leaves.filter(l => l.timeInGroupSec !== null && l.timeInGroupSec < 180 && l.msgCount === 0);
// Bouncers: joined+left multiple times
const bouncerIds = leaves.filter(l => l.leaveCount > 1).map(l => l.userId);
// Joiners by hour
const joinsByHour = Array(24).fill(0);
joins.forEach(j => joinsByHour[j.hourUTC]++);
// Language distribution of joiners
const langDist = countBy(joins.filter(j => j.lang), 'lang');
// New accounts (high ID)
const freshAccounts = joins.filter(j => j.userId > 7_500_000_000);
// Joined without premium
const noPremiumNoUsername = joins.filter(j => !j.isPremium && !j.username);

// Message patterns
const fwdMessages = messages.filter(m => m.isForward);
const urlOnly     = messages.filter(m => m.hasUrl && m.msgLen < 60);
const fwdSources  = countBy(fwdMessages.filter(m => m.fwdChatTitle), 'fwdChatTitle');
const msgsByHour  = Array(24).fill(0);
messages.forEach(m => msgsByHour[m.hourUTC]++);
// Messages from fresh accounts
const freshMsgs = messages.filter(m => m.userId > 7_500_000_000);
// Very fast posters (joined then posted within 10s)
const fastPosters = messages.filter(m => m.secSinceJoin !== null && m.secSinceJoin < 10);

// Reaction pattern
const rxByUser = {};
reactions.forEach(r => {
    if (!rxByUser[r.userId]) rxByUser[r.userId] = { count: 0, emojis: [], name: r.name, username: r.username };
    rxByUser[r.userId].count++;
    rxByUser[r.userId].emojis.push(...r.emojis);
});
const topReactors = Object.entries(rxByUser).sort((a, b) => b[1].count - a[1].count).slice(0, 5);

// Profile change / rename analysis
const suspiciousRenameWords = /\b(admin|mod|moderator|support|official|team|staff|dev|developer|founder|ceo|core|nervos|ckb)\b/i;
const suspiciousRenames = renames.filter(r =>
    suspiciousRenameWords.test(r.newName || '') && !suspiciousRenameWords.test(r.oldName || '')
);
const usernameDrops = renames.filter(r => r.oldUsername && !r.newUsername);

// Detection breakdown
const detByType = countBy(detections, 'detector');

// Ban log
let banLog = [];
for (const g of groupDirs) {
    if (fs.existsSync(g.banPath)) {
        try { banLog.push(...JSON.parse(fs.readFileSync(g.banPath, 'utf8'))); } catch {}
    }
}
const recentBans = banLog.filter(b => new Date(b.ts).getTime() >= cutoffTs);

// ── Report ──
const hr = '─'.repeat(55);
const out = [];
const line = s => out.push(s);

const groupLabel = GROUP_ARG
    ? groupDirs.map(g => g.dir).join(', ')
    : `${groupDirs.length} group(s): ${groupDirs.map(g => g.dir).join(', ')}`;

line(`\n🔍 PoPo Bot Event Analysis — last ${WINDOW_H}h — ${groupLabel}`);
line(`   ${events.length} events  (${joins.length} joins, ${leaves.length} leaves, ${messages.length} msgs, ${reactions.length} reactions)`);
line(hr);

// Joins
line(`\n📥 JOINS (${joins.length})`);
if (joins.length) {
    line(`   Fresh accounts (ID>7.5B): ${freshAccounts.length}/${joins.length} (${pct(freshAccounts.length, joins.length)})`);
    line(`   No username + no premium: ${noPremiumNoUsername.length}/${joins.length} (${pct(noPremiumNoUsername.length, joins.length)})`);
    if (langDist.length) line(`   Top languages: ${langDist.slice(0,5).map(([l,c])=>`${l}:${c}`).join(', ')}`);
    const peakHour = joinsByHour.indexOf(Math.max(...joinsByHour));
    line(`   Peak join hour (UTC): ${peakHour}:00 (${joinsByHour[peakHour]} joins)`);
}

// Leaves
line(`\n📤 LEAVES (${leaves.length})`);
line(`   Lurkers (left <3min, no msg): ${lurkers.length}/${leaves.length} (${pct(lurkers.length, leaves.length)})`);
if (lurkers.length) {
    const avgLurk = Math.round(lurkers.reduce((s,l) => s + (l.timeInGroupSec||0), 0) / lurkers.length);
    line(`   Avg lurk time: ${avgLurk}s`);
}
line(`   Repeat leave (cycling): ${bouncerIds.length} users`);

// Messages
line(`\n💬 MESSAGES (${messages.length})`);
if (messages.length) {
    line(`   Forwards: ${fwdMessages.length} (${pct(fwdMessages.length, messages.length)})`);
    line(`   URL-only: ${urlOnly.length} (${pct(urlOnly.length, messages.length)})`);
    line(`   Posted <10s after joining: ${fastPosters.length}`);
    line(`   From fresh accounts: ${freshMsgs.length}`);
    if (fwdSources.length) {
        line(`   Top forward sources:`);
        fwdSources.slice(0,5).forEach(([title, count]) => line(`     • "${title}": ${count}x`));
    }
}

// Reactions
line(`\n❤️  REACTIONS (${reactions.length})`);
if (topReactors.length) {
    line(`   Top reactors (likely honeypots):`);
    topReactors.forEach(([uid, d]) => {
        const emojiStr = [...new Set(d.emojis)].join('');
        line(`     • ${d.name || uid} (@${d.username || 'none'}) — ${d.count}x ${emojiStr}`);
    });
}

// Profile changes / renames
line(`\n🔄 PROFILE CHANGES (${renames.length})`);
if (renames.length) {
    line(`   Suspicious renames (→ authority name): ${suspiciousRenames.length}`);
    if (suspiciousRenames.length) {
        suspiciousRenames.forEach(r => line(`     ⚠️  [${r.userId}] "${r.oldName}" → "${r.newName}"`));
    }
    line(`   Username dropped (hiding identity): ${usernameDrops.length}`);
    if (usernameDrops.length) {
        usernameDrops.forEach(r => line(`     ⚠️  [${r.userId}] @${r.oldUsername} → (no username)`));
    }
    if (renames.length <= 8) {
        line(`   All changes:`);
        renames.forEach(r => {
            const t = new Date(r.ts).toISOString().slice(11,16);
            line(`     [${t}] ${r.userId}: "${r.oldName}"(@${r.oldUsername||'-'}) → "${r.newName}"(@${r.newUsername||'-'})`);
        });
    }
}

// Detections
line(`\n🚨 DETECTIONS (${detections.length})`);
if (detections.length) {
    detByType.forEach(([type, count]) => line(`   ${type}: ${count}`));
    const samples = detections.slice(-3);
    line(`   Recent:`);
    samples.forEach(d => line(`     • [${new Date(d.ts).toISOString().slice(11,19)}] ${d.detector} — "${d.textSnippet?.slice(0,60) || ''}"`));
}

// Bans
line(`\n🚫 BANS (${recentBans.length} in last ${WINDOW_H}h)`);
if (recentBans.length) {
    recentBans.forEach(b => line(`   • @${b.username || b.userId} — ${b.trigger}: ${(b.reason||'').slice(0,60)}`));
}

// Recommendations
line(`\n💡 PATTERN NOTES`);
const lurkerRate = leaves.length ? lurkers.length / leaves.length : 0;
if (lurkerRate > 0.5) line(`   ⚠️  High lurker rate (${pct(lurkers.length, leaves.length)}) — consider lowering leave-without-post threshold`);
if (freshAccounts.length > 5) line(`   ⚠️  ${freshAccounts.length} fresh accounts joined — possible bot wave`);
if (suspiciousRenames.length > 0) line(`   🚨 ${suspiciousRenames.length} authority rename(s) detected — check profile_change events above`);
if (usernameDrops.length > 0) line(`   ⚠️  ${usernameDrops.length} user(s) dropped their username — identity-hiding behaviour`);
if (fastPosters.length > 3) line(`   ⚠️  ${fastPosters.length} users posted within 10s of joining — scripted bots likely`);
if (fwdMessages.length > messages.length * 0.3) line(`   ⚠️  ${pct(fwdMessages.length, messages.length)} of messages are forwards — check sources above`);
if (detections.length === 0 && joins.length > 0) line(`   ℹ️  No detections yet — patterns accumulating, give it time`);
if (recentBans.length === 0) line(`   ℹ️  No bans in this window (dry-run or clean period)`);

line(hr);
line(`   Run: node analyse-events.js <hours>  (default: 12h)`);
line('');

console.log(out.join('\n'));
