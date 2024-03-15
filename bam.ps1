$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {

    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (Not signed, likely a cheat.)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (Hash Mismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (Not Trusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (Unknown Error)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}

Clear-Host

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "BAM Script won't work unless you run it as admin silly.."
    Start-Sleep 10
    Exit
}

Clear-Host
Write-Host -BackgroundColor Red -ForegroundColor Cyan "BAM Script written by acatto, stripped off of RedLotus."
Write-Host ""

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    Try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    } Catch {
        Write-Warning "Error Mounting HKEY_Local_Machine"
    }
}
$bv = ("bam", "bam\State")
Try {
    $Users = foreach ($ii in $bv) { Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName } }
Catch {
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}
$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\", "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias

Write-Progress -Activity "Extracting BAM keys" -Status "Please wait..." -PercentComplete 0

$progressTotal = $Users.Count * $rpath.Count
$progressCounter = 0

$Bam = foreach ($Sid in $Users) {
    foreach ($rp in $rpath) {
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property

        Write-Progress -Activity "Extracting BAM keys" -Status "Please wait..." -PercentComplete (($progressCounter++ / $progressTotal) * 100)

        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount])
            $User = $User.Value
        } catch {
            $User = ""
        }

        foreach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item

            If ($key.length -eq 24) {
                $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-", ""
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $TImeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss")
                $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Split-path -leaf ($item).TrimStart()
                } else {
                    $item
                }
                $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    ($item).Remove(1,23)
                } else {
                    $cp = ""
                }
                $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Join-Path -Path "C:" -ChildPath $cp
                } else {
                    $path = ""
                }
                $sig = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    Get-Signature -FilePath $path
                } else {
                    $sig = ""
                }
                [PSCustomObject]@{
                    'Examiner Time' = $TimeLocal
                    'Last Execution User Time' = $TimeUser
                    Application = $f
                    Path = $path
                    Signature = $Sig
                    User = $User
                }
            }
        }
    }
}

$Bam | Out-GridView -PassThru -Title "BAM key entries $($Bam.count) - some cool bam script lol"

$sw.stop()
$t = [math]::Round($sw.Elapsed.TotalMinutes, 2)

Clear-Host
Write-Host "Elapsed Time $t Minutes" -ForegroundColor DarkRed
