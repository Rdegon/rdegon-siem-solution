[CmdletBinding()]
param(
    [string]$HostName = "192.168.3.102",
    [int]$Port = 443,
    [string]$ExpectedSha256 = "9F01FC013F0E52CD2B094F000FBA005582A9963AF6064EE4DCFC2D6811ED652F"
)

$ErrorActionPreference = "Stop"
$normalizedExpected = ($ExpectedSha256 -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
if ($normalizedExpected.Length -ne 64) {
    throw "ExpectedSha256 must contain exactly 64 hexadecimal characters."
}

$tcp = [System.Net.Sockets.TcpClient]::new()
try {
    $tcp.Connect($HostName, $Port)
    $callback = {
        param(
            [object]$Sender,
            [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
            [System.Security.Cryptography.X509Certificates.X509Chain]$Chain,
            [System.Net.Security.SslPolicyErrors]$SslPolicyErrors
        )
        return $true
    }
    $stream = [System.Net.Security.SslStream]::new(
        $tcp.GetStream(),
        $false,
        $callback
    )
    try {
        $stream.AuthenticateAsClient($HostName)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $stream.RemoteCertificate.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
            )
        )
    }
    finally {
        $stream.Dispose()
    }
}
finally {
    $tcp.Dispose()
}

$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $actualSha256 = (
        [System.BitConverter]::ToString(
            $sha256.ComputeHash($certificate.RawData)
        ) -replace "-", ""
    ).ToUpperInvariant()
}
finally {
    $sha256.Dispose()
}
if ($actualSha256 -ne $normalizedExpected) {
    throw "SIEM Web certificate fingerprint mismatch. Expected $normalizedExpected, received $actualSha256."
}

$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $existing = $store.Certificates | Where-Object {
        $candidateSha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            (
                [System.BitConverter]::ToString(
                    $candidateSha256.ComputeHash($_.RawData)
                ) -replace "-", ""
            ).ToUpperInvariant() -eq $actualSha256
        }
        finally {
            $candidateSha256.Dispose()
        }
    }
    if (-not $existing) {
        $store.Add($certificate)
        Write-Output "SIEM Web certificate added to CurrentUser Root: $actualSha256"
    }
    else {
        Write-Output "SIEM Web certificate already trusted: $actualSha256"
    }
}
finally {
    $store.Close()
}
