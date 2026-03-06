/**
 * seed-members.js — build initial member baseline from recent message history
 * 
 * Fetches recent messages from the group and extracts user IDs/names
 * into a whitelist file. These users are treated as "established members"
 * and won't trigger join-based scoring (they were already here).
 *
 * Telegram limits: can only get messages the bot has seen since joining.
 * Run once after bot has been active for a few hours to seed the baseline.
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const dns  = require('dns');
dns.setDefaultResultOrder('ipv4first');
const https = require('https');

const config   = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
const GROUP_ID = config.groups[0].id;
const TOKEN    = config.bot_token;
const DATA_DIR = path.join(__dirname, 'data', GROUP_ID);
const OUT_FILE = path.join(DATA_DIR, 'member-baseline.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

function tgGet(method, params) {
    return new Promise((resolve, reject) => {
        const qs = new URLSearchParams(params).toString();
        const url = `https://api.telegram.org/bot${TOKEN}/${method}?${qs}`;
        https.get(url, res => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

async function main() {
    console.log(`Seeding member baseline for group ${GROUP_ID}...`);

    // Get admins first — always trusted
    const adminsRes = await tgGet('getChatAdministrators', { chat_id: GROUP_ID });
    const baseline = {};

    if (adminsRes.ok) {
        for (const a of adminsRes.result) {
            const u = a.user;
            baseline[u.id] = {
                id: u.id,
                username: u.username || null,
                name: [u.first_name, u.last_name].filter(Boolean).join(' '),
                role: a.status,
                is_bot: u.is_bot || false,
                seeded_at: new Date().toISOString(),
                source: 'admin_list',
            };
        }
        console.log(`  Admins seeded: ${adminsRes.result.length}`);
    }

    // Seed from recent getUpdates history (users who have messaged)
    // The bot's update buffer only goes back ~24h so run this soon after adding bot
    let offset = 0;
    let messageUsers = 0;
    const updates = await tgGet('getUpdates', {
        offset: 0,
        limit: 100,
        allowed_updates: JSON.stringify(['message', 'chat_member']),
    });

    if (updates.ok) {
        for (const u of updates.result) {
            const from = u.message?.from || u.chat_member?.new_chat_member?.user;
            if (!from || from.is_bot) continue;
            const chatId = String(u.message?.chat?.id || u.chat_member?.chat?.id);
            if (chatId !== String(GROUP_ID)) continue;
            if (!baseline[from.id]) {
                baseline[from.id] = {
                    id: from.id,
                    username: from.username || null,
                    name: [from.first_name, from.last_name].filter(Boolean).join(' '),
                    role: 'member',
                    is_bot: false,
                    seeded_at: new Date().toISOString(),
                    source: 'recent_activity',
                };
                messageUsers++;
            }
        }
        console.log(`  Active users seeded from recent messages: ${messageUsers}`);
    }

    fs.writeFileSync(OUT_FILE, JSON.stringify(baseline, null, 2));
    console.log(`\nBaseline saved: ${Object.keys(baseline).length} users → ${OUT_FILE}`);
    console.log('These users will be exempt from join-based scoring.');
}

main().catch(console.error);
