param (
    [string]$Mode,  # "encrypt" or "decrypt"
    [string]$KeyPath
)

function Generate-Key {
    $keyPath = "$PSScriptRoot\private_key.xml"
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $rsa.PersistKeyInCsp = $false
    $rsa.ToXmlString($true) | Out-File -Encoding UTF8 $keyPath
    Write-Host "🔑 Private key saved to: $keyPath"
    return $rsa
}

function Load-Key($path) {
    if (!(Test-Path $path)) {
        Write-Host "❌ Private key not found: $path"
        exit 1
    }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $rsa.PersistKeyInCsp = $false
    $rsa.FromXmlString((Get-Content $path -Raw))
    return $rsa
}

function Encrypt-Files {
    $rsa = Generate-Key
    $sourceDir = "$PSScriptRoot\files"
    $destDir = "$PSScriptRoot\encrypted"
    if (!(Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir | Out-Null
    }

    Get-ChildItem $sourceDir -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $chunkSize = 190  # RSA max input (with padding) for 2048-bit
        $encrypted = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $bytes.Length; $i += $chunkSize) {
            $block = $bytes[$i..([Math]::Min($i + $chunkSize - 1, $bytes.Length - 1))]
            $enc = $rsa.Encrypt($block, $false)
            $encrypted.AddRange($enc)
        }
        [System.IO.File]::WriteAllBytes("$destDir\$($_.Name).enc", $encrypted.ToArray())
        Write-Host "✅ Encrypted: $($_.Name)"
    }
}

function Decrypt-Files($keyPath) {
    $rsa = Load-Key $keyPath
    $sourceDir = "$PSScriptRoot\encrypted"
    $destDir = "$PSScriptRoot\decrypted"
    if (!(Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir | Out-Null
    }

    Get-ChildItem $sourceDir -Filter *.enc | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $chunkSize = 256
        $decrypted = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $bytes.Length; $i += $chunkSize) {
            $block = $bytes[$i..($i + $chunkSize - 1)]
            try {
                $plain = $rsa.Decrypt($block, $false)
                $decrypted.AddRange($plain)
            } catch {
                Write-Host "❌ Failed to decrypt chunk in: $($_.Name)"
                continue
            }
        }
        $output = "$destDir\$($_.BaseName -replace '\.enc$', '.decrypted')"
        [System.IO.File]::WriteAllBytes($output, $decrypted.ToArray())
        Write-Host "🔓 Decrypted: $($_.Name)"
    }
}

# ========================= MAIN =========================
if (!$Mode) {
    $Mode = Read-Host "Enter mode (encrypt/decrypt)"
}

switch ($Mode.ToLower()) {
    "encrypt" {
        Encrypt-Files
    }
    "decrypt" {
        if (!$KeyPath) {
            $KeyPath = Read-Host "Enter path to private key (.xml)"
        }
        Decrypt-Files $KeyPath
    }
    default {
        Write-Host "❗ Invalid mode. Use 'encrypt' or 'decrypt'."
    }
}
