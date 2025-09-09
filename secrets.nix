let
  # Your SSH public key for encryption (so you can edit secrets)
  userKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv4SpIhHJqtRaYBRQOin4PTDUxRwo7ozoQHTUFjMGLW avunu@AvunuCentral";
  
  # System SSH host key converted to age format (so the system can decrypt)
  # Get this by running: ./get-age-key.sh
  # Replace this placeholder with the actual key from your system
  systemKey = "age1v38dvwf08kk5qtf9gseqzdcufjjp49g4mr6na4z0cr3m0wrsva0sqmpch6";
in
{
  "secrets/cloudflare-email.age".publicKeys = [ userKey systemKey ];
  "secrets/cloudflare-dns-api-token.age".publicKeys = [ userKey systemKey ];
}