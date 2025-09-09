let
  # SSH public key for encryption - replace with your actual public key
  publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral";
in
{
  "secrets/cloudflare-email.age".publicKeys = [ publicKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ publicKey ];
}