# finish_stage1.ps1 - Person A, Stage 1 re-run after the 2026-10-24 changes.
# Run from the iomt-stage1 folder in the conda "base" PowerShell:
#     powershell -ExecutionPolicy Bypass -File .\finish_stage1.ps1
# Resume from a step (skips everything before it, and keeps data\processed):
#     powershell -ExecutionPolicy Bypass -File .\finish_stage1.ps1 -From csv_match
# Steps: unit, pcap_parse, device_map, build_benign, build_gate2, csv_match,
#        attack_inventory, autocorr, calibration_study, run_length, handoff, gates
# protocol.yaml changed (detectors.calibration), so a full run rebuilds
# everything from device_map onward. pcap_parse skips finished captures.
# Output is appended to results\stage1\finish_run.log.
param([string]$From = "unit")

# Python warnings go to stderr. Windows PowerShell 5 turns stderr from a native
# command into error records, so each step runs through cmd and only the exit
# code decides failure.
$ErrorActionPreference = "Continue"
$root  = $PSScriptRoot
$src   = Join-Path $root "src"
$log   = Join-Path $root "results\stage1\finish_run.log"
$order = "unit","pcap_parse","device_map","build_benign","build_gate2","csv_match",
         "attack_inventory","autocorr","calibration_study","run_length","handoff","gates"
$start = [array]::IndexOf($order, $From)
if ($start -lt 0) { "Unknown step '$From'. Steps: $($order -join ', ')"; exit 2 }
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null
"`nfinish_stage1 started $(Get-Date -Format s) from '$From'" | Out-File $log -Append -Encoding utf8

function Step($id, $dir, $cmd, [switch]$AllowFail) {
    if ([array]::IndexOf($order, $id) -lt $start) { return }
    "`n===== $id =====" | Tee-Object -FilePath $log -Append
    Push-Location $dir
    cmd /c "$cmd 2>&1" | Tee-Object -FilePath $log -Append
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0 -and -not $AllowFail) {
        "STOPPED at '$id' (exit $code). Fix it, then resume with: -From $id" | Tee-Object -FilePath $log -Append
        exit 1
    }
}

Step "unit" $root "python -m pytest tests/unit -q"

# A full run clears the streams so nothing built under an older protocol survives.
if ($start -le [array]::IndexOf($order, "build_benign") -and (Test-Path (Join-Path $root "data\processed"))) {
    Remove-Item (Join-Path $root "data\processed") -Recurse -Force
}

Step "pcap_parse"        $src "python -m iomt.streams.pcap_parse"
Step "device_map"        $src "python -m iomt.streams.device_map"
Step "build_benign"      $src "python -m iomt.streams.build benign"
Step "build_gate2"       $src "python -m iomt.streams.build gate2"
Step "csv_match"         $src "python -m iomt.streams.csv_match"
Step "attack_inventory"  $src "python -m iomt.streams.attack_inventory"
Step "autocorr"          $src "python -m iomt.audit.autocorr"
Step "calibration_study" $src "python -m iomt.validity.calibration_study"
Step "run_length"        $src "python -m iomt.validity.run_length" -AllowFail
Step "handoff"           $src "python -m iomt.handoff"
Step "gates"             $root "python -m pytest -m gate tests/gates -v" -AllowFail

"`nfinish_stage1 done $(Get-Date -Format s)" | Tee-Object -FilePath $log -Append
