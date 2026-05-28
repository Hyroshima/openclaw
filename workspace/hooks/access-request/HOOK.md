---
name: access-request
description: "Silent access request system. Detects a secret phrase from unknown senders and notifies the operator for manual approval."
metadata: { "openclaw": { "emoji": "🔑", "events": ["message:pre-auth"] } }
---

# Access Request Hook

Monitors messages from unauthorized senders.
If the message matches the configured access phrase, silently notifies the operator with the sender's ID, name, and channel, along with the exact commands needed to approve or remove the sender.
