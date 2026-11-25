# paste_sanitizer

A Tampermonkey userscript that sanitizes text **when you paste it** in the browser. It replaces IP addresses, usernames, passwords and domain names with placeholders, plus anything in your own find/replace dictionary, and shows a red warning whenever something was changed.

![Settings panel](docs/settings.png)

## Install

1. Install Tampermonkey: [Firefox add-on](https://addons.mozilla.org/en-US/firefox/addon/tampermonkey/), or see [tampermonkey.net](https://www.tampermonkey.net/) for other browsers.
2. In Tampermonkey choose **Create a new script**, replace the template with the contents of [`paste-sanitizer.user.js`](paste-sanitizer.user.js) and save.
3. To update, paste the new version over the old one the same way. The script never updates itself, and your dictionary and settings are kept.

Open the settings via the Tampermonkey menu → **⚙️ Edit dictionary & settings**.

## Internal domains & hosts

The list at the top of the settings panel is for your own domains, internal URLs and host names. Everything on it is always replaced, even when its ending isn't recognised by the domain detector (e.g. `.acme`) or the detector is switched off.

```
acme.nl
acme-corp.com => corp.example
https://wiki.intranet.acme/
fileserver01
```

| Pasted | Becomes |
|---|---|
| `https://git.acme.nl/repo`, `jan@acme.nl` | `https://host1.example.com/repo`, `jan@host2.example.com` |
| `ci.build.acme-corp.com:8080` | `ci.build.corp.example:8080` (explicit replacement keeps the subdomain) |
| `wiki.intranet.acme/pages`, `WIKI.INTRANET.ACME` | `host3.example.com/pages` (case doesn't matter) |
| `\\fileserver01\share` | `\\host4.example.com\share` |
| `notacme.nl`, `fileserver012` | not matched by the list (the domain detector may still replace `notacme.nl`) |

- One entry per line. Subdomains are included: `acme.nl` also matches `git.acme.nl` and `jan@acme.nl`.
- Without `=>`, names get the dummy domain from the detector settings (`host1.example.com`, …), numbered consistently with the domain detector.
- `domain => replacement` swaps only the domain part and keeps the subdomain.
- URLs are accepted: only the host is used (scheme, login, port and path are ignored). `*.acme.nl` works like `acme.nl`.
- A name without a dot (`fileserver01`) matches that exact word, in any case.
- Since the repo is public, the examples are fake. Your real list lives only in Tampermonkey's storage.

## Built-in detectors

Each one can be switched off in settings. They run after your keyword rules and before your regex rules (see [Order](#order)).

| Detector | Example in | Example out |
|---|---|---|
| IP addresses (IPv4 + IPv6) | `ping 10.0.0.5`, `fe80::1` | `ping IPADDR`, `IPADDR` |
| Usernames | `--user=root`, `"username": "alice"`, `ssh admin@host` | `--user=USERNAME`, `"username": "USERNAME"`, `ssh USERNAME@host` |
| Passwords | `password=hunter2`, `--password "x"`, `curl -u bob:pw` | `password=PASSWD`, `--password "PASSWD"`, `curl -u USERNAME:PASSWD` |
| Credentials in URLs | `postgres://u:p@db/app` | `postgres://USERNAME:PASSWD@host1.example.com/app` |
| Domains / FQDNs | `https://portal.acme.nl/x`, `server01.corp.acme.com` | `https://host1.example.com/x`, `host2.example.com` |
| Certificates & private keys (any PEM block) | `-----BEGIN CERTIFICATE-----` + base64 + `-----END CERTIFICATE-----` | `-----BEGIN CERTIFICATE-----` / `SSLCERT` / `-----END CERTIFICATE-----` |
| SSH public keys | `ssh-ed25519 AAAAC3Nz… john@laptop` | `ssh-ed25519 SSHKEY USERNAME@laptop` |
| Key fingerprints | `SHA256:o1IaThkt…`, `MD5:12:9e:8a:…` | `KEYFP` |

Notes:

- Usernames and passwords are only found **next to a label** (`password=`, `"user":`, `--password`, `-u`, `user:pass@`, `ssh user@`). A password on its own, like `hunter2`, can't be told apart from a normal word. Add known secrets to the dictionary instead.
- Domain names in links are always replaced. Bare domains in text are only replaced when they end in a known TLD (`.com`, `.nl`, `.io`, `.local`, `.internal`, …), so code like `window.location` or `setup.py` stays untouched. Endings that double as file extensions (`.sh`, `.py`, `.md`, `.pl`, `.rs`, …) are skipped in plain text.
- The dummy domain is configurable (default `example.com`). Different domains are numbered `host1`, `host2`, … so you can still see which lines belong together.
- Key and certificate blocks keep their `BEGIN`/`END` lines so you can still see what was pasted. The body becomes `PRIVKEY` (any private key, incl. OpenSSH, RSA, EC, PKCS#8 and PGP), `SSLCERT` (certificates and CRLs), `PUBKEY` or `PEMDATA` (anything else, e.g. a CSR). Blocks cut off before the `END` line and JSON-escaped blocks (`\n`) are handled too, as are PuTTY `.ppk` files.
- Version numbers with four parts (`1.2.3.4`) look like IPs and will be replaced.

## Dictionary format

One rule per line, top to bottom:

```
# comment
Acme Corp | Acme BV | ACME => [COMPANY]
john.doe@acme.com | jdoe | John Doe => [ME]
/(api[_-]?key\s*[:=]\s*)\S+/i => $1[REDACTED]
secret-word =>
```

- `find => replace` replaces every exact match.
- `one | two | three => replace` lists several keywords for the same replacement. Spaces around `|` are ignored, longer keywords are tried first (so `Acme Corp` is replaced whole before `Acme`), and `\|` matches a literal `|`.
- `/pattern/flags => replace` is a JavaScript regex, always replacing all matches. Use `$1`, `$2` for groups.
- Empty right side deletes the match. `\n` and `\t` work in the replacement.
- The **Try it** box in settings shows the result live while you edit.

### Order

1. **Keyword rules** (`find => replace`, `a | b => x`): your exact values win, so `john.doe@acme.com => [ME]` is applied before the domain detector can touch the email address.
2. **Built-in detectors and your internal domains**: keys and certificates first, then your internal domains list, then username, password, domain and IP.
3. **Regex rules** (`/pattern/ => x`): catch-alls like `[EMAIL]` mop up whatever is left.

Within each group, rules run top to bottom.

## Behaviour

- Only **paste** is touched. Copy and cut are untouched.
- If nothing matches, the browser's normal paste runs and formatting is kept. If something is replaced, the cleaned text is inserted as plain text.
- A red popup lists what was replaced (placeholders only, never the original values). It closes after 8 s; hover to keep it open.

  ![Red warning after a paste](docs/warning.png)

- Can be disabled per site from the Tampermonkey menu or settings.
- Settings are stored in Tampermonkey's storage. Copy the dictionary out of the settings box to back it up.
