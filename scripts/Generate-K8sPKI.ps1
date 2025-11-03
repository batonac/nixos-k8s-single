#Requires -Modules PSPKI

<#
.SYNOPSIS
    Kubernetes PKI Certificate Generation Script (PowerShell version)
    
.DESCRIPTION
    This script generates all certificates required for a Kubernetes cluster
    using the PSPKI PowerShell module instead of OpenSSL
    
.PARAMETER CertDir
    Certificate output directory
    
.PARAMETER MasterIP
    Master node IP address
    
.PARAMETER ClusterName
    Kubernetes cluster name
    
.PARAMETER ServiceCIDR
    Service network CIDR
    
.PARAMETER FQDN
    Fully qualified domain name for the cluster
    
.PARAMETER SecretsDir
    Directory to store encrypted secrets
    
.EXAMPLE
    .\Generate-K8sPKI.ps1 -MasterIP "192.168.1.100" -FQDN "k8s.example.com"
#>

[CmdletBinding()]
param(
    [string]$CertDir = ".\k8s-pki",
    [string]$MasterIP = "10.0.0.10",
    [string]$ClusterName = "kubernetes",
    [string]$ServiceCIDR = "10.96.0.0/12",
    [string]$ClusterDNS = "10.96.0.10",
    [string]$FQDN = "k3s-dev.batonac.com",
    [string]$SecretsDir = ".\secrets",
    [int]$CertValidityDays = 3650
)

# Error handling
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module PSPKI -Force
    Write-Host "[INFO] PSPKI module loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to load PSPKI module. Please install it with: Install-Module PSPKI" -ForegroundColor Red
    exit 1
}

# Logging functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Create certificate directories
function Initialize-Directories {
    Write-Info "Setting up certificate directories..."
    
    $directories = @(
        "$CertDir\ca",
        "$CertDir\etcd", 
        "$CertDir\apiserver",
        "$CertDir\kubelet",
        "$CertDir\controller-manager",
        "$CertDir\scheduler",
        "$CertDir\proxy",
        "$CertDir\service-account",
        "$CertDir\admin",
        "$CertDir\kubeconfigs",
        $SecretsDir
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}

# Encrypt and save certificate data
function Save-EncryptedCert {
    param(
        [string]$Data,
        [string]$FilePath
    )
    
    Write-Info "Saving encrypted certificate to $FilePath"
    
    # Convert to secure string and encrypt (basic approach)
    $secureString = ConvertTo-SecureString -String $Data -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString -SecureString $secureString
    
    Set-Content -Path $FilePath -Value $encrypted
}

# Decrypt certificate data
function Get-DecryptedCert {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        throw "Certificate file not found: $FilePath"
    }
    
    $encrypted = Get-Content -Path $FilePath
    $secureString = ConvertTo-SecureString -String $encrypted
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    return $plainText
}

# Generate CA certificate
function New-ClusterCA {
    Write-Info "Generating Cluster CA certificate..."
    
    # Create CA certificate
    $caParams = @{
        Subject = "CN=kubernetes-ca,O=Kubernetes"
        FriendlyName = "Kubernetes Cluster CA"
        KeyAlgorithm = "RSA"
        KeyLength = 4096
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        CertificateAuthority = $true
        KeyUsage = "CertSign", "CRLSign", "DigitalSignature", "KeyEncipherment"
    }
    
    $caCert = New-SelfSignedCertificate @caParams
    
    # Export certificate and private key
    $certPem = Get-CertificatePem -Certificate $caCert
    $keyPem = Get-PrivateKeyPem -Certificate $caCert
    
    # Save encrypted
    Save-EncryptedCert -Data $certPem -FilePath "$SecretsDir\k8s-ca.crt"
    Save-EncryptedCert -Data $keyPem -FilePath "$SecretsDir\k8s-ca.key"
    
    # Store in cert store for signing other certs
    $script:CACert = $caCert
    
    Write-Info "CA certificate generated and encrypted"
}

# Generate etcd certificates
function New-EtcdCertificates {
    Write-Info "Generating etcd certificates..."
    
    # etcd CA
    $etcdCAParams = @{
        Subject = "CN=etcd-ca,O=Kubernetes"
        FriendlyName = "etcd CA"
        KeyAlgorithm = "RSA"
        KeyLength = 4096
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        CertificateAuthority = $true
        KeyUsage = "CertSign", "CRLSign", "DigitalSignature", "KeyEncipherment"
    }
    
    $etcdCA = New-SelfSignedCertificate @etcdCAParams
    
    # Save etcd CA
    $etcdCACertPem = Get-CertificatePem -Certificate $etcdCA
    $etcdCAKeyPem = Get-PrivateKeyPem -Certificate $etcdCA
    Save-EncryptedCert -Data $etcdCACertPem -FilePath "$SecretsDir\etcd-ca.crt"
    Save-EncryptedCert -Data $etcdCAKeyPem -FilePath "$SecretsDir\etcd-ca.key"
    
    # etcd server certificate
    $etcdServerSAN = @(
        "localhost",
        "etcd.local", 
        "etcd.kube-system.svc.cluster.local",
        "127.0.0.1",
        $MasterIP
    )
    
    $etcdServerParams = @{
        Subject = "CN=etcd-server,O=Kubernetes"
        FriendlyName = "etcd Server"
        Signer = $etcdCA
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        KeyUsage = "DigitalSignature", "KeyEncipherment"
        SubjectAlternativeName = $etcdServerSAN
    }
    
    $etcdServerCert = New-SelfSignedCertificate @etcdServerParams
    
    # Save etcd server cert
    $etcdServerCertPem = Get-CertificatePem -Certificate $etcdServerCert
    $etcdServerKeyPem = Get-PrivateKeyPem -Certificate $etcdServerCert
    Save-EncryptedCert -Data $etcdServerCertPem -FilePath "$SecretsDir\etcd-server.crt"
    Save-EncryptedCert -Data $etcdServerKeyPem -FilePath "$SecretsDir\etcd-server.key"
    
    # etcd peer certificate
    $etcdPeerCert = New-SelfSignedCertificate @etcdServerParams
    $etcdPeerCert.FriendlyName = "etcd Peer"
    
    $etcdPeerCertPem = Get-CertificatePem -Certificate $etcdPeerCert
    $etcdPeerKeyPem = Get-PrivateKeyPem -Certificate $etcdPeerCert
    Save-EncryptedCert -Data $etcdPeerCertPem -FilePath "$SecretsDir\etcd-peer.crt"
    Save-EncryptedCert -Data $etcdPeerKeyPem -FilePath "$SecretsDir\etcd-peer.key"
    
    # etcd client certificates
    $etcdClientParams = @{
        FriendlyName = "etcd API Server Client"
        Subject = "CN=etcd-apiserver-client,O=Kubernetes"
        Signer = $etcdCA
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        KeyUsage = "DigitalSignature", "KeyEncipherment"
    }
    
    $etcdAPIServerClient = New-SelfSignedCertificate @etcdClientParams
    $etcdAPIServerClientPem = Get-CertificatePem -Certificate $etcdAPIServerClient
    $etcdAPIServerClientKeyPem = Get-PrivateKeyPem -Certificate $etcdAPIServerClient
    Save-EncryptedCert -Data $etcdAPIServerClientPem -FilePath "$SecretsDir\etcd-apiserver-client.crt"
    Save-EncryptedCert -Data $etcdAPIServerClientKeyPem -FilePath "$SecretsDir\etcd-apiserver-client.key"
    
    # etcd flannel client
    $etcdClientParams.Subject = "CN=etcd-flannel-client,O=Kubernetes"
    $etcdClientParams.FriendlyName = "etcd Flannel Client"
    $etcdFlannelClient = New-SelfSignedCertificate @etcdClientParams
    
    $etcdFlannelClientPem = Get-CertificatePem -Certificate $etcdFlannelClient
    $etcdFlannelClientKeyPem = Get-PrivateKeyPem -Certificate $etcdFlannelClient
    Save-EncryptedCert -Data $etcdFlannelClientPem -FilePath "$SecretsDir\etcd-flannel-client.crt"
    Save-EncryptedCert -Data $etcdFlannelClientKeyPem -FilePath "$SecretsDir\etcd-flannel-client.key"
    
    Write-Info "etcd certificates generated and encrypted"
}

# Generate API server certificate
function New-APIServerCertificate {
    Write-Info "Generating API server certificate..."
    
    $apiServerSAN = @(
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc", 
        "kubernetes.default.svc.cluster.local",
        "localhost",
        $FQDN,
        "10.43.0.1",
        $MasterIP,
        "127.0.0.1"
    )
    
    $apiServerParams = @{
        Subject = "CN=kube-apiserver,O=Kubernetes"
        FriendlyName = "Kubernetes API Server"
        Signer = $script:CACert
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        KeyUsage = "DigitalSignature", "KeyEncipherment"
        SubjectAlternativeName = $apiServerSAN
    }
    
    $apiServerCert = New-SelfSignedCertificate @apiServerParams
    
    $apiServerCertPem = Get-CertificatePem -Certificate $apiServerCert
    $apiServerKeyPem = Get-PrivateKeyPem -Certificate $apiServerCert
    Save-EncryptedCert -Data $apiServerCertPem -FilePath "$SecretsDir\k8s-apiserver.crt"
    Save-EncryptedCert -Data $apiServerKeyPem -FilePath "$SecretsDir\k8s-apiserver.key"
    
    Write-Info "API server certificate generated and encrypted"
}

# Generate client certificate for Kubernetes components
function New-ClientCertificate {
    param(
        [string]$Component,
        [string]$CommonName,
        [string]$Organization = "Kubernetes",
        [string]$SecretPrefix
    )
    
    Write-Info "Generating $Component client certificate..."
    
    $clientParams = @{
        Subject = "CN=$CommonName,O=$Organization"
        FriendlyName = "$Component Client"
        Signer = $script:CACert
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddDays($CertValidityDays)
        KeyUsage = "DigitalSignature", "KeyEncipherment"
    }
    
    $clientCert = New-SelfSignedCertificate @clientParams
    
    $clientCertPem = Get-CertificatePem -Certificate $clientCert
    $clientKeyPem = Get-PrivateKeyPem -Certificate $clientCert
    Save-EncryptedCert -Data $clientCertPem -FilePath "$SecretsDir\$SecretPrefix.crt"
    Save-EncryptedCert -Data $clientKeyPem -FilePath "$SecretsDir\$SecretPrefix.key"
    
    Write-Info "$Component client certificate generated and encrypted"
}

# Generate service account keys
function New-ServiceAccountKeys {
    Write-Info "Generating service account keys..."
    
    # Generate RSA key pair
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $privateKeyPem = Get-RSAPrivateKeyPem -RSA $rsa
    $publicKeyPem = Get-RSAPublicKeyPem -RSA $rsa
    
    Save-EncryptedCert -Data $publicKeyPem -FilePath "$SecretsDir\k8s-service-account.crt"
    Save-EncryptedCert -Data $privateKeyPem -FilePath "$SecretsDir\k8s-service-account.key"
    
    Write-Info "Service account keys generated and encrypted"
}

# Generate kubeconfig file
function New-KubeConfig {
    param(
        [string]$User,
        [string]$CertPath,
        [string]$KeyPath,
        [string]$OutputPath
    )
    
    Write-Info "Generating kubeconfig for $User..."
    
    $caCertPem = Get-DecryptedCert -FilePath "$SecretsDir\k8s-ca.crt"
    $clientCertPem = Get-DecryptedCert -FilePath $CertPath
    $clientKeyPem = Get-DecryptedCert -FilePath $KeyPath
    
    $caData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($caCertPem))
    $certData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($clientCertPem))
    $keyData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($clientKeyPem))
    
    $kubeconfig = @"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: $caData
    server: https://${FQDN}:6443
  name: $ClusterName
contexts:
- context:
    cluster: $ClusterName
    user: $User
  name: $User@$ClusterName
current-context: $User@$ClusterName
users:
- name: $User
  user:
    client-certificate-data: $certData
    client-key-data: $keyData
"@

    Save-EncryptedCert -Data $kubeconfig -FilePath $OutputPath
    Write-Info "Kubeconfig for $User generated and encrypted"
}

# Helper functions for PEM conversion
function Get-CertificatePem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    
    $certBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certBase64 = [Convert]::ToBase64String($certBytes)
    
    $pem = "-----BEGIN CERTIFICATE-----`n"
    for ($i = 0; $i -lt $certBase64.Length; $i += 64) {
        $line = $certBase64.Substring($i, [Math]::Min(64, $certBase64.Length - $i))
        $pem += "$line`n"
    }
    $pem += "-----END CERTIFICATE-----"
    
    return $pem
}

function Get-PrivateKeyPem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    
    $rsa = $Certificate.GetRSAPrivateKey()
    $keyBytes = $rsa.ExportRSAPrivateKey()
    $keyBase64 = [Convert]::ToBase64String($keyBytes)
    
    $pem = "-----BEGIN RSA PRIVATE KEY-----`n"
    for ($i = 0; $i -lt $keyBase64.Length; $i += 64) {
        $line = $keyBase64.Substring($i, [Math]::Min(64, $keyBase64.Length - $i))
        $pem += "$line`n"
    }
    $pem += "-----END RSA PRIVATE KEY-----"
    
    return $pem
}

function Get-RSAPrivateKeyPem {
    param([System.Security.Cryptography.RSA]$RSA)
    
    $keyBytes = $RSA.ExportRSAPrivateKey()
    $keyBase64 = [Convert]::ToBase64String($keyBytes)
    
    $pem = "-----BEGIN RSA PRIVATE KEY-----`n"
    for ($i = 0; $i -lt $keyBase64.Length; $i += 64) {
        $line = $keyBase64.Substring($i, [Math]::Min(64, $keyBase64.Length - $i))
        $pem += "$line`n"
    }
    $pem += "-----END RSA PRIVATE KEY-----"
    
    return $pem
}

function Get-RSAPublicKeyPem {
    param([System.Security.Cryptography.RSA]$RSA)
    
    $keyBytes = $RSA.ExportRSAPublicKey()
    $keyBase64 = [Convert]::ToBase64String($keyBytes)
    
    $pem = "-----BEGIN RSA PUBLIC KEY-----`n"
    for ($i = 0; $i -lt $keyBase64.Length; $i += 64) {
        $line = $keyBase64.Substring($i, [Math]::Min(64, $keyBase64.Length - $i))
        $pem += "$line`n"
    }
    $pem += "-----END RSA PUBLIC KEY-----"
    
    return $pem
}

# Main execution
function Invoke-Main {
    Write-Info "Starting Kubernetes PKI certificate generation..."
    Write-Info "Master IP: $MasterIP"
    Write-Info "Service CIDR: $ServiceCIDR"
    Write-Info "FQDN: $FQDN"
    
    try {
        Initialize-Directories
        
        # Generate CA
        New-ClusterCA
        
        # Generate etcd certificates  
        New-EtcdCertificates
        
        # Generate API server certificate
        New-APIServerCertificate
        
        # Generate service account keys
        New-ServiceAccountKeys
        
        # Generate client certificates for components
        New-ClientCertificate -Component "admin" -CommonName "kubernetes-admin" -Organization "system:masters" -SecretPrefix "k8s-admin"
        New-ClientCertificate -Component "controller-manager" -CommonName "system:kube-controller-manager" -SecretPrefix "k8s-controller-manager"
        New-ClientCertificate -Component "scheduler" -CommonName "system:kube-scheduler" -SecretPrefix "k8s-scheduler"  
        New-ClientCertificate -Component "proxy" -CommonName "system:kube-proxy" -SecretPrefix "k8s-proxy"
        New-ClientCertificate -Component "kubelet" -CommonName "system:node:$env:COMPUTERNAME" -Organization "system:nodes" -SecretPrefix "k8s-kubelet"
        
        # Generate kubeconfig files
        New-KubeConfig -User "admin" -CertPath "$SecretsDir\k8s-admin.crt" -KeyPath "$SecretsDir\k8s-admin.key" -OutputPath "$SecretsDir\k8s-admin.kubeconfig"
        New-KubeConfig -User "controller-manager" -CertPath "$SecretsDir\k8s-controller-manager.crt" -KeyPath "$SecretsDir\k8s-controller-manager.key" -OutputPath "$SecretsDir\k8s-controller-manager.kubeconfig"
        New-KubeConfig -User "scheduler" -CertPath "$SecretsDir\k8s-scheduler.crt" -KeyPath "$SecretsDir\k8s-scheduler.key" -OutputPath "$SecretsDir\k8s-scheduler.kubeconfig"
        New-KubeConfig -User "kube-proxy" -CertPath "$SecretsDir\k8s-proxy.crt" -KeyPath "$SecretsDir\k8s-proxy.key" -OutputPath "$SecretsDir\k8s-proxy.kubeconfig"
        New-KubeConfig -User "kubelet" -CertPath "$SecretsDir\k8s-kubelet.crt" -KeyPath "$SecretsDir\k8s-kubelet.key" -OutputPath "$SecretsDir\k8s-kubelet.kubeconfig"
        
        Write-Info "Certificate generation completed successfully!"
        Write-Info ""
        Write-Info "All certificates and kubeconfig files are encrypted in: $SecretsDir"
        Write-Info "To decrypt the admin kubeconfig:"
        Write-Info "  `$config = Get-DecryptedCert -FilePath '$SecretsDir\k8s-admin.kubeconfig'"
        Write-Info "  `$config | Out-File -FilePath '~\.kube\config' -Encoding UTF8"
        
    } catch {
        Write-Error "Certificate generation failed: $($_.Exception.Message)"
        exit 1
    }
}

# Execute main function
Invoke-Main
