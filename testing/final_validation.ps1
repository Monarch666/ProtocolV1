
# FINAL VALIDATION ORCHESTRATION SCRIPT
# This script runs the full UAVLink security testbed and captures attack results.

$LogFile = "testing/final_security_audit.log"
"Starting Final Security Audit..." | Out-File -FilePath $LogFile

# 1. Clean up any existing processes
Stop-Process -Name uav_simulator, gcs_receiver, python -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 2. Launch the Adversarial Proxy
$ProxyLog = "testing/proxy_audit.log"
Remove-Item $ProxyLog -ErrorAction SilentlyContinue
Start-Process python -ArgumentList "testing/adversarial_test.py" -RedirectStandardOutput $ProxyLog -RedirectStandardError "$ProxyLog.err" -WindowStyle Hidden -WorkingDirectory (Get-Location)
"Proxy launched." | Out-File -FilePath $LogFile -Append
Start-Sleep -Seconds 2

# 3. Launch UAV Simulator
$UavLog = "testing/uav_audit.log"
Remove-Item $UavLog -ErrorAction SilentlyContinue
Start-Process "bin/uav_simulator.exe" -ArgumentList "127.0.0.1 --send-port 14550 --listen-port 14553" -RedirectStandardOutput $UavLog -RedirectStandardError "$UavLog.err" -WindowStyle Hidden -WorkingDirectory (Get-Location)
"UAV launched." | Out-File -FilePath $LogFile -Append
Start-Sleep -Seconds 2

# 4. Launch GCS Receiver (with auto-soak)
$GcsLog = "testing/gcs_audit.log"
Remove-Item $GcsLog -ErrorAction SilentlyContinue
Start-Process "bin/gcs_receiver.exe" -ArgumentList "127.0.0.1 --send-port 14551 --listen-port 14552 --auto-soak" -RedirectStandardOutput $GcsLog -RedirectStandardError "$GcsLog.err" -WindowStyle Hidden -WorkingDirectory (Get-Location)
"GCS launched." | Out-File -FilePath $LogFile -Append

Write-Host "Monitoring for 20 seconds..."
Start-Sleep -Seconds 20

# 5. Check Results
if (Test-Path $GcsLog) {
    if (Select-String -Path $GcsLog -Pattern "session ESTABLISHED") {
        "[PASS] Security Session ESTABLISHED over proxy." | Out-File -FilePath $LogFile -Append
    } else {
        "[FAIL] Handshake FAILED during security audit!" | Out-File -FilePath $LogFile -Append
    }
}

if (Test-Path $ProxyLog) {
    "--- Proxy Attack Activity ---" | Out-File -FilePath $LogFile -Append
    Select-String -Path $ProxyLog -Pattern "REPLAY|BIT-FLIP|TAMPER" | Select-Object -First 10 | Out-File -FilePath $LogFile -Append
}

# 6. Cleanup
Stop-Process -Name uav_simulator, gcs_receiver, python -Force -ErrorAction SilentlyContinue

"Audit Complete." | Out-File -FilePath $LogFile -Append
Get-Content $LogFile
