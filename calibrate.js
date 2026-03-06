#!/usr/bin/env node
/**
 * calibrate.js — CKB Anti-Scam Bot Learn Mode Calibration
 *
 * Reads predictions.jsonl + admin-actions.jsonl from each group's data dir.
 * Outputs precision/recall per detector, recommended threshold changes,
 * and a summary of missed threats (FALSE_NEGATIVE patterns).
 *
 * Usage:
 *   node calibrate.js [--days 14] [--group "Nervos Network"]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const args   = process.argv.slice(2);
const DAYS   = parseInt(args[args.indexOf('--days') + 1] || '14', 10);
const FILTER_GROUP = args[args.indexOf('--group') + 1] || null;
const cutoff = Date.now() - DAYS * 24 * 3600 * 1000;

// ── Load all predictions ──────────────────────────────────────────────────────
const groups = [];
for (const g of (config.groups || [])) {
    const name    = g.name || g.id;
    if (FILTER_GROUP && name !== FILTER_GROUP) continue;
    const dataDir = path.join(__dirname, 'data', String(g.id));
    const predFile = path.join(dataDir, 'predictions.jsonl');
    const adminFile = path.join(dataDir, 'admin-actions.jsonl');

    if (!fs.existsSync(predFile)) {
        console.log(`[${name}] No predictions.jsonl yet — bot hasn't been running long enough.`);
        continue;
    }

    const predictions = fs.readFileSync(predFile, 'utf8')
        .split('\n').filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean)
        .filter(p => p.ts >= cutoff);

    const adminActions = fs.existsSync(adminFile)
        ? fs.readFileSync(adminFile, 'utf8')
            .split('\n').filter(Boolean)
            .map(l => { try { return JSON.parse(l); } catch { return null; } })
            .filter(Boolean)
            .filter(a => a.ts >= cutoff)
        : [];

    groups.push({ name, predictions, adminActions });
}

if (!groups.length) {
    console.log('No data to analyse yet. Run the bot for a few days first.');
    process.exit(0);
}

// ── Analysis ──────────────────────────────────────────────────────────────────
for (const { name, predictions, adminActions } of groups) {
    console.log('\n' + '═'.repeat(60));
    console.log(`📊  ${name} — Last ${DAYS} days`);
    console.log('═'.repeat(60));

    // Overall counts
    const total    = predictions.length;
    const tp       = predictions.filter(p => p.outcome === 'TRUE_POSITIVE').length;
    const fp       = predictions.filter(p => p.outcome === 'FALSE_POSITIVE').length;
    const fn       = predictions.filter(p => p.outcome === 'FALSE_NEGATIVE').length;
    const pending  = predictions.filter(p => p.outcome === null).length;

    const precision = tp + fp > 0 ? (tp / (tp + fp) * 100).toFixed(1) : 'N/A';
    const recall    = tp + fn > 0 ? (tp / (tp + fn) * 100).toFixed(1) : 'N/A';
    const f1        = (precision !== 'N/A' && recall !== 'N/A')
        ? (2 * tp / (2 * tp + fp + fn) * 100).toFixed(1) : 'N/A';

    console.log(`\n📈  Overall (${total} predictions, ${pending} still pending)`);
    console.log(`    TRUE_POSITIVE  (correct bans)  : ${tp}`);
    console.log(`    FALSE_POSITIVE (wrong flags)   : ${fp}`);
    console.log(`    FALSE_NEGATIVE (missed threats): ${fn}`);
    console.log(`    Precision : ${precision}%`);
    console.log(`    Recall    : ${recall}%`);
    console.log(`    F1 Score  : ${f1}%`);

    // ── Per-detector breakdown ────────────────────────────────────────────────
    const detectors = {};
    for (const p of predictions) {
        if (!p.trigger || p.outcome === null) continue;
        if (!detectors[p.trigger]) detectors[p.trigger] = { tp: 0, fp: 0, fn: 0 };
        if (p.outcome === 'TRUE_POSITIVE')  detectors[p.trigger].tp++;
        if (p.outcome === 'FALSE_POSITIVE') detectors[p.trigger].fp++;
        if (p.outcome === 'FALSE_NEGATIVE') detectors[p.trigger].fn++;
    }

    if (Object.keys(detectors).length) {
        console.log('\n🔍  Per-detector breakdown:');
        const rows = Object.entries(detectors).map(([trigger, d]) => {
            const prec  = d.tp + d.fp > 0 ? (d.tp / (d.tp + d.fp) * 100).toFixed(0) : 'N/A';
            const rec   = d.tp + d.fn > 0 ? (d.tp / (d.tp + d.fn) * 100).toFixed(0) : 'N/A';
            const total = d.tp + d.fp + d.fn;
            const recommendation = recDetector(d);
            return { trigger, tp: d.tp, fp: d.fp, fn: d.fn, total, prec, rec, recommendation };
        }).sort((a, b) => b.total - a.total);

        for (const r of rows) {
            console.log(`\n    [${r.trigger}]`);
            console.log(`      TP: ${r.tp}  FP: ${r.fp}  FN: ${r.fn}  (n=${r.total})`);
            console.log(`      Precision: ${r.prec}%  Recall: ${r.rec}%`);
            if (r.recommendation) console.log(`      ⚠️  ${r.recommendation}`);
        }
    }

    // ── FALSE_NEGATIVE patterns ───────────────────────────────────────────────
    const fnPreds = predictions.filter(p => p.outcome === 'FALSE_NEGATIVE');
    if (fnPreds.length) {
        console.log(`\n🚨  FALSE NEGATIVES — threats bot missed (${fnPreds.length}):`);
        for (const p of fnPreds.slice(0, 10)) {
            console.log(`    [${p.iso}] User ${p.userId} — admin action: ${p.adminAction || 'unknown'}`);
        }
        if (fnPreds.length > 10) console.log(`    ... and ${fnPreds.length - 10} more`);
    }

    // ── Admin actions not predicted ───────────────────────────────────────────
    const adminBans = adminActions.filter(a => a.action === 'ban' || a.action === 'kick');
    const predictedUserIds = new Set(predictions.filter(p => p.outcome === 'TRUE_POSITIVE').map(p => p.userId));
    const totallyMissed = adminBans.filter(a => !predictedUserIds.has(a.targetUserId));

    if (totallyMissed.length) {
        console.log(`\n🔎  Admin bans/kicks with NO bot prediction (${totallyMissed.length}):`);
        for (const a of totallyMissed.slice(0, 5)) {
            console.log(`    [${a.iso}] User ${a.targetUserId} (@${a.targetUsername || 'unknown'}) — banned by @${a.actorUsername || a.actorId}`);
        }
        if (totallyMissed.length > 5) console.log(`    ... and ${totallyMissed.length - 5} more`);
        console.log(`    → Consider reviewing these users' messages for new pattern signals`);
    }

    // ── Recommendations ───────────────────────────────────────────────────────
    console.log('\n💡  Recommendations:');

    if (fp > tp) {
        console.log('    ⬆️  Bot is over-triggering (more false positives than true). Increase score thresholds.');
    } else if (fn > tp * 0.5) {
        console.log('    ⬇️  Bot is missing too many threats. Lower score thresholds or add patterns.');
    } else if (parseFloat(precision) >= 80 && parseFloat(recall) >= 70) {
        console.log('    ✅  Precision and recall look healthy. Consider enabling live mode.');
    } else if (pending > total * 0.3) {
        console.log('    ⏳  Many predictions still pending (< 48h). Re-run in a few days.');
    } else {
        console.log('    📊  Continue monitoring. Need more data for reliable recommendations.');
    }

    // ── Summary for MEMORY.md update ─────────────────────────────────────────
    console.log('\n📝  Summary (for MEMORY.md):');
    console.log(`    Group: ${name} | Period: ${DAYS}d | Predictions: ${total}`);
    console.log(`    Precision: ${precision}% | Recall: ${recall}% | F1: ${f1}%`);
    console.log(`    TP: ${tp} | FP: ${fp} | FN: ${fn} | Pending: ${pending}`);
}

// ── Helper: per-detector recommendation ──────────────────────────────────────
function recDetector(d) {
    if (d.tp + d.fp < 3) return 'Too few samples — keep monitoring';
    const prec = d.tp / (d.tp + d.fp);
    const rec  = d.tp + d.fn > 0 ? d.tp / (d.tp + d.fn) : 1;
    if (prec < 0.5) return 'High false positive rate — consider raising this detector\'s score weight';
    if (rec  < 0.4) return 'Low recall — this detector is missing real threats, consider lowering threshold';
    if (prec >= 0.85 && rec >= 0.75) return '✅ Performing well';
    return null;
}

console.log('\n' + '═'.repeat(60));
console.log('Run again after more data accumulates (recommend 2 weeks minimum).');
console.log('To go live: set "dry_run": false in config.json for each group.');
