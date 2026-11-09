# PhishGuard

A Java web application that checks a web address for phishing signs, gives it a risk score from 0 to 100%, and explains the verdict on a browser dashboard. Every scan is saved in a MySQL database, and the dashboard sits behind a login page.

Built as a group mini project by Cyrus Anklesaria, Allan and Rishon Brass (Computer Engineering).

## Features

- **Phishing detection** using URL checks and page content checks, all rule based and explainable
- **Risk score** from 0 to 100% with three levels: Safe (below 30), Suspicious (30-64) and Phishing (65 and above)
- **Dashboard** with a risk gauge, a card for every finding with advice, and a technical log
- **MySQL scan history** through JDBC, shown in a History table on the dashboard
- **Login and logout** with accounts stored in MySQL (passwords are salted and hashed with PBKDF2)
- **REST API** built on Java's built-in HTTP server, with a rate limiter and an SSRF check on the URLs it fetches
- **Automated tests** (7 tests)

## How detection works

| Check | Example |
|---|---|
| Look-alike brand names (Levenshtein similarity of 70% or more) | `paypa1` looks like `paypal` |
| IP address used as the host | `http://192.168.1.100/secure-signin` |
| Look-alike or Punycode characters | Cyrillic letters in a domain |
| Many nested subdomains | `paypal.com.verify.account.example.top` |
| Risky domain endings and high-entropy names | `.top`, `.xyz` |
| Suspicious keywords and plain HTTP | `login`, `verify`, `http://` |
| Page content | Brand title mismatch, form posting to another site, password fields, hidden text, external scripts |

Each finding adds weighted points, capped at 100. The weights add up to the final score.

## Requirements

- Windows with a JDK 17 or newer (JDK 21 works). Get Temurin from https://adoptium.net and tick "Add to PATH" and "Set JAVA_HOME".
- XAMPP with MySQL started (Apache is not needed, but phpMyAdmin is handy for viewing the data)
- MySQL Connector/J: download the platform independent ZIP from https://dev.mysql.com/downloads/connector/j/ and copy the `.jar` file into the `lib` folder

If MySQL or the driver is missing, the app still runs and keeps scan history and accounts in memory instead.

## Run it

1. Start **MySQL** in the XAMPP Control Panel.
2. Double-click **`run.bat`** (or run `powershell -ExecutionPolicy Bypass -File .\build_and_run.ps1`). It compiles the code, runs the tests and starts the server.
3. Open **http://localhost:8080** and log in with the demo account `admin` / `admin123`, or create your own account.
4. Paste a URL and click Scan. Leave the window open while you use the app.

The database `phishguard` and its tables are created automatically. You can view them in phpMyAdmin at http://localhost/phpmyadmin.

## Try these addresses

| URL | Expected score |
|---|---|
| `https://www.google.com` | 0% Safe |
| `http://paypa1-verify-account.com/login` | 55% Suspicious |
| `http://paypa1.com.secure-login.verify-account.top/login` | 70% Phishing |
| `http://paypal.com.account-update.verify-user.top/auth` | 90% Phishing |
| `http://192.168.1.100/secure-signin` | 100% Phishing |

## REST API

All endpoints except `/health` and the login endpoints need a logged-in session.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/auth/login` | Log in with `{"username":"...","password":"..."}` |
| POST | `/api/v1/auth/register` | Create an account |
| POST | `/api/v1/auth/logout` | Log out |
| GET | `/api/v1/auth/me` | Name of the logged-in user |
| POST | `/api/v1/scan` | Scan a URL with `{"url":"..."}` |
| GET | `/api/v1/history` | The 50 most recent scans |
| GET | `/api/v1/samples` | Sample URLs for the Quick Test buttons |
| GET | `/api/v1/health` | Server and database status |

## Database

Two tables are used: `scans` (one row per scan: URL, score, risk level, attack type, time) and `users` (username and password hash). The SQL is in `database/schema.sql`, and the connection settings are in `db.properties` (default XAMPP user `root` with an empty password).

## Project structure

```
PhishGuard/
  src/com/phishguard/
    engine/    URL and content analysers, scoring engine, Levenshtein
    model/     ScanResult, RiskFactor, PhishingType
    security/  RateLimiter, SSRF validator
    service/   PhishingScannerService, HistoryService, UserService
    server/    HTTP server and REST handlers
    test/      PhishingDetectionTest
  web/         login page and dashboard (HTML, CSS, JavaScript)
  database/    schema.sql
  lib/         put the MySQL Connector/J jar here
  db.properties, run.bat, build_and_run.ps1, SETUP_XAMPP.md
```

## Notes

- This is a rule-based demonstration project, so a few legitimate sites can be flagged as Suspicious (false positives).
- The `admin` / `admin123` account is for demonstration only.
