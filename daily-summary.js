#!/usr/bin/env node
/**
 * daily-summary.js — CKB Anti-Scam Bot Daily Stats Summary
 *
 * Generates a daily stats digest: threats detected, admin actions,
 * hit rates, top triggers, and learn mode accuracy.
 *
 * Usage:
 *   node daily-summary.js [--days 1] [--notify] [--save]
 *
 * --days N     Summarise last N days (default: 1 = yesterday/today)
 * --notify     Send summary to Telegram alert chat
 * --save       Append to data/<groupId>/daily-stats.jsonl
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const dns   = require('dns');
dns.setDefaultResultOrder('ipv4first');
const https = require('https');

const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const args   = process.argv.slice(2);
const DAYS   = parseInt(args[args.indexOf('--days') + 1] || '1', 10);
const NOTIFY = args.includes('--notify');
const SAVE   = args.includes('--save');
const now    = Date.now();
const cutoff = now - DAYS * 24 * 3600 * 1000;

// ── Telegram helper ───────────────────────────────────────────────────────────
function tgSend(token, chatId, text) {
    return new Promise((resolve) => {
        const body = JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' });
        const req = https.request({
            hostname: 'api.telegram.org',
            path: `/bot${token}/sendMessage`,
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, res => { res.resume(); resolve(); });
        req.on('error', () => resolve());
        req.write(body);
        req.end();
    });
}

// ── Load + parse event log ────────────────────────────────────────────────────
function loadJsonl(file) {
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, 'utf8')
        .split('\n').filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean);
}

const summaries = [];

for (const g of (config.groups || [])) {
    const name     = g.name || g.id;
    const dataDir  = path.join(__dirname, 'data', String(g.id));
    const alertChat = g.alert_chat || g.id;

    const events      = loadJsonl(path.join(dataDir, 'event-log.jsonl')).filter(e => e.ts >= cutoff);
    const predictions = loadJsonl(path.join(dataDir, 'predictions.jsonl')).filter(e => e.ts >= cutoff);
    const adminActs   = loadJsonl(path.join(dataDir, 'admin-actions.jsonl')).filter(e => e.ts >= cutoff);

    if (!events.length && !predictions.length && !adminActs.length) {
        console.log(`[${name}] No data in last ${DAYS}d yet.`);
        continue;
    }

    // ── Event breakdown ───────────────────────────────────────────────────────
    const joins        = events.filter(e => e.type === 'join');
    const leaves       = events.filter(e => e.type === 'leave');
    const messages     = events.filter(e => e.type === 'message');
    const detections   = events.filter(e => e.type === 'detection');
    const bans         = events.filter(e => e.type === 'ban');
    const profileChgs  = events.filter(e => e.type === 'profile_change');

    // ── Prediction accuracy ───────────────────────────────────────────────────
    const preds        = predictions.filter(p => p.outcome !== null);
    const tp           = preds.filter(p => p.outcome === 'TRUE_POSITIVE').length;
    const fp           = preds.filter(p => p.outcome === 'FALSE_POSITIVE').length;
    const fn           = preds.filter(p => p.outcome === 'FALSE_NEGATIVE').length;
    const pending      = predictions.filter(p => p.outcome === null).length;

    const precision    = tp + fp > 0 ? (tp / (tp + fp) * 100).toFixed(1) : null;
    const recall       = tp + fn > 0 ? (tp / (tp + fn) * 100).toFixed(1) : null;

    // ── Top triggers ─────────────────────────────────────────────────────────
    const triggerCounts = {};
    for (const d of detections) {
        const t = d.detector || d.trigger || 'unknown';
        triggerCounts[t] = (triggerCounts[t] || 0) + 1;
    }
    for (const p of predictions) {
        if (!p.trigger || p.trigger === 'missed') continue;
        triggerCounts[p.trigger] = (triggerCounts[p.trigger] || 0) + 1;
    }
    const topTriggers = Object.entries(triggerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    // ── Admin action summary ──────────────────────────────────────────────────
    const adminBans    = adminActs.filter(a => a.action === 'ban');
    const adminKicks   = adminActs.filter(a => a.action === 'kick');
    const adminRestr   = adminActs.filter(a => a.action === 'restrict');

    // ── Peak activity hour ────────────────────────────────────────────────────
    const hourCounts = {};
    for (const e of events) {
        const h = new Date(e.ts).getUTCHours();
        hourCounts[h] = (hourCounts[h] || 0) + 1;
    }
    const peakHour = Object.entries(hourCounts).sort((a, b) => b[1] - a[1])[0];

    // ── Build summary object ──────────────────────────────────────────────────
    const summary = {
        date:       new Date().toISOString().slice(0, 10),
        group:      name,
        period_days: DAYS,
        activity: {
            joins:          joins.length,
            leaves:         leaves.length,
            messages_seen:  messages.length,
            profile_changes: profileChgs.length,
        },
        threats: {
            total_detections: detections.length + predictions.filter(p => p.action === 'ban').length,
            bot_flags:        predictions.length,
            bot_bans:         bans.length,
            admin_bans:       adminBans.length,
            admin_kicks:      adminKicks.length,
            admin_restricts:  adminRestr.length,
        },
        accuracy: {
            true_positives:  tp,
            false_positives: fp,
            false_negatives: fn,
            pending,
            precision_pct:   precision ? parseFloat(precision) : null,
            recall_pct:      recall    ? parseFloat(recall)    : null,
        },
        top_triggers: Object.fromEntries(topTriggers),
        peak_hour_utc: peakHour ? parseInt(peakHour[0]) : null,
    };

    summaries.push({ summary, alertChat });

    // ── Console output ────────────────────────────────────────────────────────
    const label = DAYS === 1 ? 'Today' : `Last ${DAYS}d`;
    console.log(`\n${'═'.repeat(55)}`);
    console.log(`🛡️  ${name} — ${label} (${new Date().toISOString().slice(0, 10)})`);
    console.log('═'.repeat(55));
    console.log(`\n📊 Activity`);
    console.log(`   Joins: ${joins.length}  Leaves: ${leaves.length}  Messages: ${messages.length}  Profile changes: ${profileChgs.length}`);
    console.log(`\n⚠️  Threats`);
    console.log(`   Bot flags: ${predictions.length}  Bot bans (dry-run): ${bans.length}`);
    console.log(`   Admin bans: ${adminBans.length}  Admin kicks: ${adminKicks.length}  Admin restricts: ${adminRestr.length}`);

    if (topTriggers.length) {
        console.log(`\n🔍 Top triggers:`);
        for (const [t, c] of topTriggers) console.log(`   ${t}: ${c}`);
    }

    if (preds.length > 0) {
        console.log(`\n🎯 Learn mode accuracy (${preds.length} resolved predictions + ${pending} pending):`);
        console.log(`   TP: ${tp}  FP: ${fp}  FN: ${fn}`);
        if (precision) console.log(`   Precision: ${precision}%  Recall: ${recall}%`);
    } else {
        console.log(`\n🎯 Learn mode: ${pending} predictions pending (< 48h — too early to score)`);
    }

    if (peakHour) console.log(`\n⏰ Peak activity: ${peakHour[0]}:00 UTC (${peakHour[1]} events)`);

    // ── Save to daily-stats.jsonl ─────────────────────────────────────────────
    if (SAVE) {
        const statsFile = path.join(dataDir, 'daily-stats.jsonl');
        // Avoid duplicate entries for same date+period
        let existing = [];
        if (fs.existsSync(statsFile)) {
            existing = fs.readFileSync(statsFile, 'utf8').split('\n').filter(Boolean)
                .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        }
        const isDupe = existing.some(e => e.date === summary.date && e.period_days === summary.period_days && e.group === summary.group);
        if (!isDupe) {
            fs.appendFileSync(statsFile, JSON.stringify(summary) + '\n');
            console.log(`\n💾 Saved to daily-stats.jsonl`);
        }
    }
}

// ── Send Telegram notifications ───────────────────────────────────────────────
if (NOTIFY && summaries.length) {
    (async () => {
        for (const { summary: s, alertChat } of summaries) {
            const label = s.period_days === 1 ? 'Daily' : `${s.period_days}d`;
            const acc = s.accuracy;
            const accLine = acc.precision_pct !== null
                ? `🎯 Accuracy: ${acc.precision_pct}% precision / ${acc.recall_pct}% recall (TP:${acc.true_positives} FP:${acc.false_positives} FN:${acc.false_negatives})`
                : `🎯 Learn mode: ${acc.pending} predictions pending`;

            const topLine = Object.entries(s.top_triggers).length
                ? '🔍 Top triggers: ' + Object.entries(s.top_triggers).map(([t, c]) => `${t}(${c})`).join(', ')
                : '';

            const msg = [
                `🛡️ *Anti-Scam ${label} Summary — ${s.group}*`,
                `📅 ${s.date}`,
                ``,
                `📊 *Activity*`,
                `Joins: ${s.activity.joins} · Leaves: ${s.activity.leaves} · Messages: ${s.activity.messages_seen}`,
                ``,
                `⚠️ *Threats*`,
                `Bot flags: ${s.threats.bot_flags} · Bot bans (dry): ${s.threats.bot_bans}`,
                `Admin bans: ${s.threats.admin_bans} · Kicks: ${s.threats.admin_kicks}`,
                ``,
                accLine,
                topLine,
            ].filter(Boolean).join('\n');

            await tgSend(config.bot_token, alertChat, msg);
            console.log(`\n📨 Summary sent to ${alertChat}`);
        }
    })();
}

if (!summaries.length) console.log('\nNo data yet — bot needs more time in the group.');
