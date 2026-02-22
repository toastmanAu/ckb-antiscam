# CKB Anti-Scam Bot

Protects the @NervosUnofficial Telegram group from fake moderator scams.

## What it catches

| Attack | Detection | Action |
|--------|-----------|--------|
| Fake mod joins with similar name | Levenshtein ≤ 2 edits from any real mod's name | Instant ban on join |
| Fake mod copies profile photo | Perceptual hash similarity (hamming ≤ 10) | Instant ban on join |
| Scammer asks people to DM them | Regex patterns on every message | Delete + ban (or warn) |
| Claims to be admin/official | Regex patterns on every message | Delete + instant ban |
| Any combination of above | Multi-signal scoring | Ban with reason log |

## Setup

### 1. Create a Telegram Bot
1. Message @BotFather → `/newbot`
2. Get your bot token
3. Add the bot to @NervosUnofficial as an **admin** with:
   - ✅ Ban users
   - ✅ Delete messages  
   - ✅ Restrict members

### 2. Configure

```bash
cp config.example.json config.json
nano config.json
```

Fill in:
- `bot_token` — your new bot's token from BotFather
- `chat_id` — your group's chat ID (e.g. -1001338982855)
- `mods` — array of ALL real moderators:

```json
{
  "bot_token": "1234567890:AAFxxxx",
  "chat_id": "-1001338982855",
  "alert_chat": "-1001338982855",
  "mods": [
    {
      "name": "Phill",
      "username": "toastmanAu",
      "user_id": 1790655432
    },
    {
      "name": "OtherMod",
      "username": "othermod_username",
      "user_id": 9876543210
    }
  ],
  "name_dist_threshold": 2,
  "photo_hash_threshold": 10,
  "warn_first": true
}
```

**Finding user IDs:** Forward a message from each mod to @userinfobot

### 3. Run

```bash
# One-shot:
bash start.sh

# Or as a systemd service (auto-restart):
systemctl --user enable ckb-antiscam
systemctl --user start ckb-antiscam
systemctl --user status ckb-antiscam
```

## Commands (mod-only)

| Command | Description |
|---------|-------------|
| `/checkme` | Test: run detection on yourself (won't ban mods) |
| `/refreshhashes` | Re-fetch mod profile photo hashes |
| `/bans [N]` | Show last N bans (default 5) |

## Tuning

| Setting | Default | Meaning |
|---------|---------|---------|
| `name_dist_threshold` | 2 | Max edit distance before flagging name as fake |
| `photo_hash_threshold` | 10 | Max hamming distance before flagging photo as copy |
| `warn_first` | true | Warn before banning DM-bait messages (false = instant ban) |

**Lower = stricter.** If you get false positives, increase thresholds.
If scammers are slipping through, decrease them.

## How photo detection works

1. On startup, bot downloads each mod's current profile photo
2. Computes an 8x8 average perceptual hash (64-bit)
3. For each new user, fetches their photo and computes the same hash
4. Compares using Hamming distance — identical = 0, very similar ≤ 10
5. Hashes refresh automatically every 6 hours

This catches even slightly modified photos (colour-adjusted, cropped, recompressed).

## Ban log

All bans are written to `ban-log.json`:
```json
[
  {
    "userId": 123456789,
    "username": "ph1ll_admin",
    "reason": "Name 'Phill' is 1 edit from mod 'Phill'; DM-baiting message",
    "triggeredBy": "message-check",
    "ts": "2026-03-15T04:23:11.000Z"
  }
]
```

## Adding more mods

Edit `config.json` → add to `mods` array → run `/refreshhashes` in the group.

---

Built by [toastmanAu](https://github.com/toastmanAu) · Part of the Nervos community tooling
