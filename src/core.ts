/**
 * Pure, dependency-free core for dsh-plugin-plan-preview (Plan & Risk Preview).
 * Reads only metadata from session events; never prompts, tool bodies or file contents.
 */

const SECRET_RE = /((?:token|key|secret|password|authorization|bearer)[^\s:=]{0,24}[:=]\s*)[^\s&]+/gi
const QUERY_RE = /([?&](?:token|key|secret|password|auth)=)[^&#\s]+/gi
/** Strip credential-looking substrings before anything is printed. */
export function redact(value: unknown): string {
  const text = value instanceof Error ? value.stack || value.message : String(value)
  return text.replace(SECRET_RE, '$1[redacted]').replace(QUERY_RE, '$1[redacted]')
}
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

const RISK_RE = /\b(delete|remove|drop|overwrite|force|sudo|rm\s+-|publish|deploy|pay|transfer)\b/i

export function analyze(events: readonly unknown[]): any {
  const list = Array.isArray(events) ? events : []
  const steps: any[] = []
  for (const e of list) {
    if (!isRecord(e) || !isRecord(e.data)) continue
    const t = e.type
    if (t === 'tool/call' || t === 'tool/start' || t === 'tool/request') {
      const name = typeof e.data.name === 'string' ? e.data.name : 'tool'
      const args = JSON.stringify(e.data.arguments ?? e.data.args ?? {})
      const risky = RISK_RE.test(name + ' ' + args)
      steps.push({ kind: 'tool', name, risky })
    } else if (t === 'model/request' || t === 'request/header') {
      steps.push({ kind: 'model', name: 'model-call', risky: false })
    }
  }
  const risky = steps.filter(s => s.risky).length
  const dependsOnPrior = steps.length > 1
  return {
    sampledEvents: list.length,
    steps,
    total: steps.length,
    risky,
    hasDependency: dependsOnPrior,
    needsConfirmation: risky > 0,
  }
}

export function formatReport(a: any, opts: { json?: boolean } = {}): string {
  if (opts.json) return JSON.stringify(a, null, 2)
  const head = '[plan-preview] ' + a.total + ' planned step(s) · ' + a.risky + ' risky' +
    (a.hasDependency ? ' · sequential dependency' : '')
  if (a.steps.length === 0) return head + '\n  no plan steps observed yet'
  const lines = a.steps.slice(0, 20).map((s, i) =>
    '  ' + (i + 1) + '. ' + redact(s.name) + (s.risky ? '  ⚠ risky — confirm' : ''))
  return [head, ...lines].join('\n') + (a.needsConfirmation ? '\nConfirm risky steps before they run.' : '')
}
