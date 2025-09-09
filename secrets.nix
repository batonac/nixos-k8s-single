let
  # Your SSH public key for encryption (so you can edit secrets)
  userKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral";
  
  # System SSH host key (so the system can decrypt)
  # Get this by running: ssh-keyscan -t ed25519 k3s-dev.batonac.com
  systemKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKcK5TIl7+2rXEdWqcgkz7+4HM4G2teWaIZxI7Q8L8k0"; # REPLACE WITH ACTUAL SYSTEM SSH KEY
in
{
  # Cloudflare secrets only
  "secrets/cloudflare-email.age".publicKeys = [ userKey systemKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ userKey systemKey ];
}