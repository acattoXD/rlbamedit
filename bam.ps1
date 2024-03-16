$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {

  [CmdletBinding()]
  param(
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
  exit
}

Clear-Host
Write-Host -BackgroundColor Red -ForegroundColor Cyan "BAM Script written by acatto, credits to RedLotus for Signature Check, discord.gg/redlotus"
Write-Host ""

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
  try {
    New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
  } catch {
    Write-Warning "Error Mounting HKEY_Local_Machine"
  }
}
$bv = ("bam","bam\State")
try {
  $Users = foreach ($ii in $bv) { Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName } }
catch {
  Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
  exit
}
$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias


$Bam = foreach ($Sid in $Users) {
  foreach ($rp in $rpath) {
    Write-Progress -Id 1 -Activity "$($rp)"
    $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
    Write-Progress -Id 2 -Activity "Collecting Security ID (sid) entries" -Status "($($Users.Count)) sid: $($objSID.value)" -ParentId 1
    try {
      $objSID = New-Object System.Security.Principal.SecurityIdentifier ($Sid)
      $User = $objSID.Translate([System.Security.Principal.NTAccount])
      $User = $User.Value
    }
    catch { $User = "" }
    $i = 0
    foreach ($Item in $BamItems) { $i++
      $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
      Write-Progress -Id 3 -Activity "Collecting BAM entries for SID: $($objSID.value)" -Status "(Entry $i of $($BamItems.Count))" -ParentId 1
      if ($key.length -eq 24) {
        $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-",""
        $Bias = - ([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
        $TImeUser = (Get-Date ([datetime]::FromFileTimeUtc([Convert]::ToInt64($Hex,16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss")
        $f = if ((((Split-Path -Path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
          Split-Path -Leaf ($item).TrimStart()
        } else {
          $item
        }
        $cp = if ((((Split-Path -Path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
          ($item).Remove(1,23)
        } else {
          $cp = ""
        }
        $path = if ((((Split-Path -Path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
          Join-Path -Path "C:" -ChildPath $cp
        } else {
          $path = ""
        }
        $sig = if ((((Split-Path -Path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
          Get-Signature -FilePath $path
        } else {
          $sig = ""
        }
        [pscustomobject]@{
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
$t = [math]::Round($sw.Elapsed.TotalMinutes,2)

Clear-Host
Write-Host "Elapsed Time: $t Minutes" -ForegroundColor Red
