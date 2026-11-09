# PhishGuard: MySQL (XAMPP + phpMyAdmin) setup

## One-time setup
1. Install XAMPP and open the **XAMPP Control Panel**.
2. Click **Start** next to **MySQL** (Apache is only needed if you want phpMyAdmin).
3. Download the MySQL JDBC driver (see `lib/README.txt`) and put the `.jar` in `lib/`.
4. Optional: in phpMyAdmin (http://localhost/phpmyadmin) open **Import** and choose
   `database/schema.sql`. If you skip this, the app creates the `phishguard` database
   and `scans` table by itself on first start.
5. If your MySQL root user has a password, set it in `db.properties`
   (XAMPP default is user `root`, empty password).

## Run
Open PowerShell in the PhishGuard folder and run:

    .\build_and_run.ps1

Look for this line in the console:

    [HistoryService] Connected to MySQL. Scan history is saved in table 'scans'.

Then open http://localhost:8080 and scan a few URLs.

## Check it works (screenshots for the report)
- http://localhost:8080/api/v1/health shows `"database":{"connected":true,"status":"MySQL connected"}`.
- phpMyAdmin > `phishguard` > `scans` > **Browse** shows each scan as a row.
- Stop the server (Ctrl+C), start it again, and open the History section:
  the earlier scans are still listed.

## Troubleshooting
| Console message | Fix |
| --- | --- |
| `No suitable driver found` | The jar is missing from `lib/`. |
| `Communications link failure` / `Connection refused` | Start MySQL in the XAMPP Control Panel; check the port (default 3306). |
| `Access denied for user 'root'` | Put the right password in `db.properties`. |
| Driver errors mentioning MariaDB | XAMPP ships MariaDB. If Connector/J gives trouble, use the MariaDB Connector/J jar and set `db.url=jdbc:mariadb://localhost:3306/phishguard`. |

While MySQL is unavailable the app still runs and keeps the last 50 scans in memory;
`/api/v1/health` then reports `"connected":false`.

## Running on a new Windows PC
1. Extract the zip first (right-click > Extract All). Do not run from inside the zip.
2. Install a JDK (Temurin 17 or 21 from https://adoptium.net, tick "Add to PATH" and "Set JAVA_HOME"), then open a new window.
3. Start MySQL in the XAMPP Control Panel and put the MySQL Connector/J .jar in the `lib` folder.
4. Double-click `run.bat`. The window stays open so any error can be read.
   (If you prefer PowerShell: `powershell -ExecutionPolicy Bypass -File .\build_and_run.ps1`)
