# PhishGuard Build & Execution Helper Script (MySQL / XAMPP edition)
# Run this from inside the PhishGuard folder:  .\build_and_run.ps1
Set-Location $PSScriptRoot
if ($PSScriptRoot -like "*\AppData\Local\Temp*" -or -not (Test-Path "src")) {
    Write-Host "The 'src' folder was not found next to this script." -ForegroundColor Red
    Write-Host "If you opened the .zip directly, right-click it > Extract All first, then run from the extracted PhishGuard folder."
    Read-Host "Press Enter to close this window"; exit 1
}

# ---- Find a JDK (needs javac.exe, a plain JRE is not enough) ----
function Find-Tool($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $roots = @()
    if ($env:JAVA_HOME) { $roots += $env:JAVA_HOME }
    $bases = @(
        "C:\Program Files\Java",
        "C:\Program Files\Eclipse Adoptium",
        "C:\Program Files\Microsoft",
        "C:\Program Files\Amazon Corretto",
        "C:\Program Files\Zulu",
        "C:\Program Files\BellSoft",
        "C:\Program Files (x86)\Java"
    )
    foreach ($base in $bases) {
        if (Test-Path $base) {
            $roots += Get-ChildItem $base -Directory | ForEach-Object { $_.FullName }
        }
    }
    foreach ($root in $roots) {
        $candidate = Join-Path $root "bin\$name.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$javac = Find-Tool "javac"
if (-not $javac) {
    Write-Host "================================================="
    Write-Host " Java JDK not found (javac.exe is missing)."
    Write-Host " 1. Download JDK 17 or 21 (.msi) from https://adoptium.net"
    Write-Host " 2. In the installer, enable 'Add to PATH' and 'Set JAVA_HOME'."
    Write-Host " 3. Close this PowerShell window, open a new one, and check:  javac -version"
    Write-Host " 4. Run .\build_and_run.ps1 again."
    Write-Host "================================================="
    Read-Host "Press Enter to close this window"; exit 1
}
$java = Join-Path (Split-Path $javac) "java.exe"
if (-not (Test-Path $java)) { $java = Find-Tool "java" }

Write-Host "================================================="
Write-Host " Building PhishGuard Detection System..."
Write-Host " Compiler: $javac"
Write-Host "================================================="

# MySQL JDBC driver check
$driver = Get-ChildItem "lib" -Filter "*.jar" -ErrorAction SilentlyContinue
if (-not $driver) {
    Write-Warning "No MySQL driver found in lib\. Download mysql-connector-j (Platform Independent ZIP) from https://dev.mysql.com/downloads/connector/j/ and copy the .jar into lib\. The app will use in-memory history until you do."
} else {
    Write-Host " JDBC driver: $($driver[0].Name)"
}
Write-Host " Make sure MySQL is started in the XAMPP Control Panel."

# Create bin directory
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# Collect Java sources
$sources = Get-ChildItem -Path "src" -Filter "*.java" -Recurse | Select-Object -ExpandProperty FullName
Write-Host "Compiling $($sources.Count) Java source files..."

& $javac -d bin -sourcepath src $sources
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation Failed!"
    Read-Host "Press Enter to close this window"; exit 1
}

Write-Host "Compilation Successful!"
Write-Host "================================================="
Write-Host " Running Automated Verification Tests..."
Write-Host "================================================="

$cp = "bin;lib/*"
& $java -cp $cp com.phishguard.test.PhishingDetectionTest
if ($LASTEXITCODE -ne 0) {
    Write-Error "Verification Tests Failed!"
    Read-Host "Press Enter to close this window"; exit 1
}

Write-Host "================================================="
Write-Host " Starting PhishGuard Embedded Server..."
Write-Host " Open Browser at: http://localhost:8080"
Write-Host " View data in phpMyAdmin: http://localhost/phpmyadmin  (database: phishguard, table: scans)"
Write-Host "================================================="

& $java -cp $cp com.phishguard.server.PhishGuardServer
Write-Host "Server stopped."
Read-Host "Press Enter to close this window"
