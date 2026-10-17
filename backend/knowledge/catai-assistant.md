---
id: catai-assistant
title: What CatAI is and what it can do
keywords: [catai, assistant, ai, what are you, who are you, what can you do, help, chat, capabilities, local, private, ollama]
questions:
  - What is CatAI?
  - What can you do?
  - Who are you?
  - Is my data sent anywhere?
  - Do you remember our previous conversation?
related: [getting-started]
actions: []
---

CatAI is a small local assistant built into this dashboard. It answers from CatWAF's own documentation and can see your real, current settings — the security score, whether the engine is on, what's blocked — so answers reflect your actual system, not a generic guide.

## What it can do

- Answer questions about how CatWAF's features work, in plain language.
- Look at your real configuration to answer things like "is my site actually protected?"
- Carry out requests that make protection **stronger** immediately — "block traffic from China," "set paranoia to 3," "turn on rate limiting" — with a one-click Undo right after.
- Offer to carry out requests that would make protection **weaker** — allowing an IP through, unblocking something — but always asks you to confirm first. It never does those silently.

## What it deliberately can't do

Some things aren't in its toolbox at all — not hidden behind a confirmation, just not reachable: turning the engine off, switching to detection-only, or disabling rate limiting. For those, it'll explain what the setting does and point you to the real control, because a change that reduces your protection is a decision worth making deliberately, on the actual settings page.

## Privacy

By default CatAI talks to Ollama at `http://127.0.0.1:11434`. Prompts can include your question, selected settings and sanitized recent log fields. If an administrator sets `OLLAMA_URL` to another host, that host receives the prompts. Use only an endpoint and network path you trust. The initial model download also needs network access.

## Memory

Each question is answered fresh — CatAI doesn't remember earlier messages in the conversation. If a follow-up needs context from what you asked before, just include it again in your next message.

## It can be wrong

CatAI runs on a small model so it stays fast on modest hardware. It's good at explaining CatWAF's own features accurately, but treat any specific recommendation as a suggestion to verify, not a final answer — especially before applying something you're not sure about.
