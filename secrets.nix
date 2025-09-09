let
  # Your SSH public key for encryption
  userKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral";
in
{
  "secrets/cloudflare-email.age".publicKeys = [ userKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ userKey ];
}