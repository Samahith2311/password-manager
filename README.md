# Vaultly - Password Manager

A simple, private password manager that runs entirely in your web browser. Your passwords are encrypted on your own device and are never sent to any server.

Built with plain HTML, CSS and JavaScript. There is no framework, no build step and no backend.

> **Note:** This is a learning project and has not had a professional security review. For your most important passwords (email, banking), a maintained password manager such as Bitwarden is the safer choice.

## Features

- **Master password** with strong encryption (AES-256-GCM, key derived with PBKDF2 and 600,000 rounds)
- **Store any login:** title, username or email, password, website, category and notes
- **Search** across title, username, website and category
- **Password generator** with adjustable length and character types, using secure randomness
- **Strength meter** that scores passwords and flags common patterns
- **Auto-lock** after inactivity (1 to 30 minutes, you choose)
- **Clipboard clearing** 20 seconds after you copy a password
- **Encrypted backup and restore** as a `.json` file
- **CSV import** from Chrome and Edge password exports
- **Breach check** using the Have I Been Pwned "Pwned Passwords" service (see below)
- **Security overview** with a score and lists of weak, reused, breached and old passwords
- **Dark mode** that follows your system and remembers your choice

## How it works

| Part | What it does |
| --- | --- |
| Master password | Never stored. It is turned into an encryption key each time you unlock. |
| Key derivation | PBKDF2 with SHA-256, 600,000 iterations and a random salt |
| Encryption | AES-256-GCM with a fresh random IV on every save |
| Storage | Only the encrypted data is saved, in your browser's local storage |
| Memory | The key and your entries exist in memory only while the vault is unlocked |

## Privacy

- All encryption and decryption happens in your browser using the built-in Web Crypto API.
- The breach check is the only feature that uses the internet. It sends only the **first 5 characters of the SHA-1 hash** of a password (a method called k-anonymity). Your password, and the rest of its hash, never leave your device.
- Nothing is sent to any server owned by this project. There is no account, no tracking and no analytics.

## Run it locally

1. Download or clone this repository.
2. Open the folder in VS Code and start it with the **Live Server** extension, or run any simple local server, for example:

```bash
   python -m http.server 8000
```

3. Open `http://localhost:8000` in your browser.

## Deploy with GitHub Pages

1. Push the files to a GitHub repository, with `index.html` in the root folder.
2. In the repository, go to **Settings**, then **Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select the `main` branch and the `/ (root)` folder, then click **Save**.
4. After a minute or so, your site is live at `https://YOUR-USERNAME.github.io/REPOSITORY-NAME/`.

## Important things to know

- **Your vault lives in one browser.** Data is stored per browser and per website address. A different browser, a different computer, or the hosted site versus `localhost` each start with an empty vault.
- **Back up regularly.** Use **Backup and import**, then **Export encrypted backup**, and keep the file somewhere safe.
- **There is no password recovery.** If you forget your master password, your data cannot be recovered.
- **Clearing site data deletes your vault.** Export a backup first.
- **Delete CSV files after importing them.** A CSV export from a browser holds your passwords as plain text.
- **Only run this from a source you trust.** Anything that can run scripts on the page could read your passwords while the vault is unlocked.

## Project structure

```
password-manager/
├── index.html   # page structure and the three screens
├── style.css    # light and dark themes and layout
├── app.js       # encryption, vault, generator, backup, breach check
└── README.md
```

## Possible next steps

- Change master password (re-encrypt the vault with a new one)
- Delay after repeated failed unlock attempts
- Passphrase generator
- Installable app support (PWA)

## License

Add a license of your choice here. If you are unsure, the [MIT License](https://choosealicense.com/licenses/mit/) is a common, permissive option.