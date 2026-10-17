
const express = require('express')
const rateLimit = require('express-rate-limit')
const router = express.Router()

const { writeRequired } = require('../middleware/auth')
const auditSvc = require('../services/audit')
const logger = require('../services/logger')
const log = logger.child('catai')

const ollama = require('../services/catai/ollama')
const retrieval = require('../services/catai/retrieval')
const extract = require('../services/catai/extract')
const actions = require('../services/catai/actions')
const undo = require('../services/catai/undo')
const promptSvc = require('../services/catai/prompt')
const queries = require('../services/catai/queries')

const ENABLED = process.env.CATAI_ENABLED === 'true'

const chatLimiterPerMin = rateLimit({
  windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.user?.username || req.ip,
  message: { detail: 'Too many questions — wait a moment and try again.', code: 'CATAI_RATE_LIMIT' },
})
const chatLimiterPerDay = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.user?.username || req.ip,
  message: { detail: 'Daily question limit reached.', code: 'CATAI_RATE_LIMIT' },
})
const actionLimiter = rateLimit({
  windowMs: 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.user?.username || req.ip,
  message: { detail: 'Too many changes applied in the last minute — wait before applying more.', code: 'CATAI_RATE_LIMIT' },
})

router.get('/api/catai/status', async (req, res) => {
  if (!ENABLED) return res.json({ configured: false, detail: 'CatAI is disabled (CATAI_ENABLED=false).' })
  const s = await ollama.status()
  res.json(s)
})

async function resolveTurn(message, req) {
  if (req.user.role !== 'admin') {
    return { actionOutcome: null, retrievalResult: retrieval.search(message) }
  }

  let extracted = extract.extractAction(message)
  const retrievalResult = retrieval.search(message)

  if (!extracted) {
    const candidateActions = [...new Set([
      ...(retrievalResult.confident ? (retrievalResult.docs[0].actions || []) : []),
      ...actions.candidatesFor(message),
    ])].slice(0, 5)
    const tools = actions.toolSchemasFor(candidateActions)
    if (tools.length) {
      const call = await ollama.toolCall(message, tools).catch(() => null)
      const actionId = call && actions.actionIdForToolName(call.name)
      if (actionId) extracted = { actionId, params: actions.normalizeToolArgs(actionId, call.arguments), complete: true }
    }
  }

  if (!extracted) return { actionOutcome: null, retrievalResult }

  if (!extracted.complete) {
    return {
      actionOutcome: { kind: 'incomplete', actionId: extracted.actionId, missing: extracted.missing },
      retrievalResult,
    }
  }

  const prepared = actions.prepare(extracted.actionId, extracted.params, req)
  if (!prepared.ok) {
    return { actionOutcome: { kind: 'error', actionId: extracted.actionId, error: prepared.error }, retrievalResult }
  }

  if (prepared.direction === 'strengthen') {
    const applied = actions.apply(extracted.actionId, extracted.params, req)
    const undoId = undo.record({ actionId: extracted.actionId, params: extracted.params, prev: applied.prev, user: req.user.username })
    return {
      actionOutcome: {
        kind: 'applied', actionId: extracted.actionId, params: extracted.params,
        message: applied.message, undoId, caddyReloaded: applied.caddy_reloaded,
      },
      retrievalResult,
    }
  }

  return {
    actionOutcome: {
      kind: 'offer', actionId: extracted.actionId, params: extracted.params,
      label: prepared.label, warn: prepared.warn,
    },
    retrievalResult,
  }
}

function lowerFirst(s) { return String(s).charAt(0).toLowerCase() + String(s).slice(1) }

function actionResultText(outcome) {
  if (!outcome) return null
  switch (outcome.kind) {
    case 'applied': return `Done: ${outcome.message}.`
    case 'offer': return `Not done yet: you have offered to ${lowerFirst(outcome.label)}, and are waiting for them to confirm.`
    case 'incomplete': return `They want this done but haven't said which ${outcome.missing}. Ask them for the ${outcome.missing}, in your own words.`
    case 'error': return `The requested change could not be made: ${outcome.error}`
    default: return null
  }
}

router.post('/api/catai/chat', chatLimiterPerDay, chatLimiterPerMin, async (req, res) => {
  const message = (req.body && req.body.message)
  if (typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ detail: 'message is required' })
  }
  if (Buffer.byteLength(message, 'utf8') > 8192) return res.status(400).json({ detail: 'message exceeds 8192 UTF-8 bytes' })
  if (!ENABLED) return res.status(503).json({ detail: 'CatAI is disabled.', code: 'CATAI_DISABLED' })

  req.setTimeout(0)
  res.setTimeout(0)
  res.set({ 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' })

  const send = (frame) => { try { res.write(JSON.stringify(frame) + '\n') } catch {} }
  req.on('close', () => {})

  try {
    send({ t: 'status', v: 'thinking', detail: 'Reading your message…' })

    const { actionOutcome, retrievalResult } = await resolveTurn(message.trim(), req)

    if (actionOutcome?.kind === 'applied') {
      send({ t: 'status', v: 'acted', detail: actionOutcome.message })
      auditSvc.audit(req, 'catai.chat.action', actionOutcome.actionId, { kind: 'applied' })
    }

    const live = await queries.resolve(message.trim(), {
      onStage: () => send({ t: 'status', v: 'lookup', detail: 'Checking your live stats…' }),
    })

    const built = await promptSvc.assemble({
      userMessage: message.trim(),
      actionResult: actionResultText(actionOutcome)
        ? { rendered: actionResultText(actionOutcome), applied: actionOutcome.kind === 'applied' }
        : null,
      retrievalResult,
      liveData: live ? live.text : null,
      onStage: (stage, detail) => {
        const label = {
          retrieval: 'Looking through my notes…',
          doc: detail ? `Reading ${detail}` : null,
          config: 'Checking your settings…',
          logs: 'Looking at recent blocked requests…',
          generate: 'Writing…',
        }[stage]
        if (label) send({ t: 'status', v: stage, detail: label })
      },
    })

    // Size only, never the prompt itself — it carries the operator's question
    // and the live configuration context retrieved for it.
    log.debug('CatAI prompt built', { user: req.user.username, chars: built.prompt.length })

    let full = ''
    await ollama.generateStream(built.prompt, (tok) => { full += tok; send({ t: 'token', v: tok }) })

    const CLAIMS_DONE_RE = /\b(?:i|i've|i have)\s+(?:now\s+|just\s+)?(block|unblock|disabl|enabl|set|chang|appl|add|remov|updat|turn|creat)(?:ed|d)?\b/i

    let correction = null

    if (!actionOutcome && CLAIMS_DONE_RE.test(full)) {
      correction = "I can explain this, but I can't act on it from here — see the docs above for how to do it in the dashboard."
    }

    if ((actionOutcome?.kind === 'offer' || actionOutcome?.kind === 'incomplete') && CLAIMS_DONE_RE.test(full)) {
      correction = actionOutcome.kind === 'offer'
        ? `To be clear: I haven't done that yet — nothing has changed. Use the confirm button above if you want me to go ahead.`
        : `To be clear: I haven't done that yet — I still need the ${actionOutcome.missing} before I can.`
    }

    if (actionOutcome?.kind === 'applied'
        && /\b(i can(?:'|no)?t|i am (?:not )?un(?:able)|you(?:'ll| will) need to|you can do this|unable to)\b/i.test(full)) {
      correction = `Ignore that last part — I did make the change: ${actionOutcome.message} You can undo it with the button above.`
    }

    if (correction) send({ t: 'correction', v: correction })

    if (actionOutcome && actionOutcome.kind !== 'error') {
      send({ t: 'action', v: actionOutcome })
    }

    send({ t: 'done', v: { sources: built.docIds } })
  } catch (e) {
    log.warn('CatAI chat error', { error: e.message, code: e.code })
    send({ t: 'error', code: e.code || 'CATAI_ERROR', detail: e.code === 'CATAI_BUSY' ? e.message : 'Something went wrong answering that — try again.' })
  } finally {
    res.end()
  }
})

router.post('/api/catai/apply', writeRequired, actionLimiter, (req, res) => {
  const { actionId, params } = req.body || {}
  if (typeof actionId !== 'string') return res.status(400).json({ detail: 'actionId is required' })
  // Weakening actions keep the same human-in-the-loop rule here as in chat:
  // the caller must explicitly acknowledge that this is a weakening change.
  // The dashboard sends this flag from the Apply button; a stray or
  // confused-deputy call cannot silently lower protection.
  try {
    if (actions.directionOf(actionId, params || {}) === actions.DIRECTION.WEAKEN && req.body?.confirm_weaken !== true) {
      return res.status(400).json({ detail: 'This change weakens protection — it needs explicit confirmation.', code: 'WEAKEN_CONFIRMATION_REQUIRED' })
    }
  } catch { /* unknown actions fail below with a clearer error */ }
  const applied = actions.apply(actionId, params || {}, req)
  if (!applied.ok) return res.status(400).json({ detail: applied.error })
  const undoId = undo.record({ actionId, params: params || {}, prev: applied.prev, user: req.user.username })
  auditSvc.audit(req, 'catai.chat.action', actionId, { kind: 'confirmed' })
  res.json({ message: applied.message, undoId, caddy_reloaded: applied.caddy_reloaded })
})

router.post('/api/catai/undo', writeRequired, (req, res) => {
  const { undoId } = req.body || {}
  const entry = typeof undoId === 'string' && undo.find(undoId)
  if (!entry) return res.status(404).json({ detail: 'Nothing to undo — that entry is unknown or already undone.' })
  if (entry.undone) return res.status(400).json({ detail: 'That change was already undone.' })
  const result = actions.restore(entry.prev, req)
  if (!result.ok) return res.status(400).json({ detail: result.error })
  undo.markUndone(undoId)
  res.json({ message: 'Reverted.', caddy_reloaded: result.caddy_reloaded })
})

module.exports = router
