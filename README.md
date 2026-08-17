# RGSecurityTeam — Cookie / Session Hijacking Lab

An offline, Dockerized web app for teaching **reflected XSS → cookie theft → account takeover**,
with three difficulty levels (Low / Medium / High).

> ⚠️ **Educational use only.** Run this only on your own machine / isolated network.
> Do not expose it to the public internet. Do not reuse the vulnerable patterns in real projects.

## Run it

```bash
docker compose up --build
```

Then open **http://localhost:5000**

(Or without compose: `docker build -t rgsecurity-lab . && docker run -p 5000:5000 rgsecurity-lab`)

## Flow for the video

1. **Register** two accounts — one "victim", one "attacker" (use two browsers or normal + incognito).
2. Login as the victim, go to a level, and find the input that isn't sanitised properly.
3. Inject a payload that runs `alert(document.cookie)` — this proves script execution and shows
   the victim's `auth_token` cookie value on screen.
4. Copy that token, open the **Hijack Simulator** (`/hijack`) as the "attacker", paste the token,
   and you're logged in as the victim — full account takeover, no password needed.

## The three levels

Each level exposes the same three injection points: the **search bar**, the **category dropdown**
(query-string parameter, so it can be edited even though the UI only shows fixed options), and the
**comment box + Post button**.

| Level | Filter behaviour | Idea to demonstrate |
|---|---|---|
| **Low** | No filtering at all. | Straight `<script>alert(document.cookie)</script>` works. |
| **Medium** | Strips a literal `<script>...</script>` block. | Filter only thinks about `<script>` tags — an `<img src=x onerror=alert(document.cookie)>` sails right through. |
| **High** | Strips `<script>`, `</script>`, and common `on*=` handlers — but only in a single, non-recursive pass. | Removing an inner match can cause the leftover characters to re-form a blocked pattern, e.g. `<scr<script>ipt>...` becomes `<script>...` after the filter runs once. This is a very common real-world filter-evasion bug — worth explaining on camera with a diagram of "before → after filter → after re-scan mentally". |

The exact payloads are intentionally not pre-filled anywhere in the UI so you can "discover" them live for the video — but they're documented here for your prep / script-writing.

## What makes this deliberately vulnerable (don't ship this pattern for real!)

- `auth_token` cookie is set with `httponly=False`, so client-side JavaScript can read it.
- Search/category/comment inputs are rendered with Jinja2 `|safe`, after passing through weak filters.
- Passwords are stored in plaintext in SQLite (kept simple on purpose, so the video stays focused on
  cookies/XSS rather than password hashing).
- `/hijack` accepts any valid token and logs the browser in as that user — simulating what an attacker
  does with a stolen cookie.

## Resetting the lab

Comments are stored in memory and users in `lab.db` (SQLite). Restarting the container wipes both,
so you get a clean lab for each take:

```bash
docker compose down
docker compose up --build
```
