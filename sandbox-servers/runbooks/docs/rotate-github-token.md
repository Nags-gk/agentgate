# Rotate a leaked GitHub token

1. Revoke the token at github.com/settings/tokens (or the org's fine-grained token page).
2. Search the audit log for calls made with it since the leak window.
3. Create a replacement with the narrowest repository access, and store it in AgentGate's vault.
4. Open a SEC ticket with the timeline. Never paste the token value into chat or tickets.
