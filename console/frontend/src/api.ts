import { reactive, watch } from 'vue'

const BASE: string = (import.meta.env.VITE_API_BASE as string) || 'http://localhost:8080'
const POLL_MS = 3000

export type Range = '15m' | '1h' | '24h'
export type Page = 'overview' | 'workloads' | 'events' | 'incidents' | 'rules' | 'nodes' | 'settings'

export interface Point { t: number; v: number }
export interface Overview {
  kpis: { workloads: number; events_per_sec: number; kills: number; kills_total: number; audit_dropped: number; rules: number; agents: number }
  events_series: Point[]
  kills_series: Point[]
  state_breakdown: Record<string, number>
}
export interface Workload { pod: string; namespace: string; node: string; comm: string; rule: string; state: string; action: string }
export interface AEvent { ts_ns: number; severity: string; pod: string; namespace: string; rule: string; event: string; node: string; action: string; enforced: boolean }
export interface Rule { name: string; scope: string; num_states: number; window_ns: number; terminal_action: string; hits: number }
export interface NodeInfo { node: string; kernel: string; hooks_attached: number; hooks_total: number; status: string; events_per_sec: number }
export interface Settings { enforce: boolean; metrics_addr: string; bundle: { rules: unknown }; audit_ring_bytes: number; kernel: string }
export interface Incident { pod: string; namespace: string; node: string; rule: string; started_ts_ns: number; ended_ts_ns: number; max_state: string; outcome: string; steps: number }
export interface ChainStep { ts_ns: number; state: string; event: string; action: string; enforced: boolean }

export const store = reactive({
  page: 'overview' as Page,
  range: '15m' as Range,
  customFrom: 0,
  customTo: 0,
  evAll: false,
  brushing: false,
  offline: false,
  loaded: false,
  wlFilter: 'all',
  wlQ: '',
  evSev: 'all',
  evQ: '',
  chainPod: '',
  chainModalPod: '',
  modalChain: [] as ChainStep[],
  incidents: [] as Incident[],
  muted: [] as string[],
  overview: null as Overview | null,
  allWorkloads: [] as Workload[],
  workloads: [] as Workload[],
  allEvents: [] as AEvent[],
  events: [] as AEvent[],
  rules: [] as Rule[],
  nodes: [] as NodeInfo[],
  settings: null as Settings | null,
  chain: [] as ChainStep[],
})

async function req<T>(method: string, path: string, params: Record<string, string> = {}, body?: unknown): Promise<T> {
  const u = new URL(BASE + path)
  for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v)
  const r = await fetch(u.toString(), {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status}`)
  const text = await r.text()
  return (text ? JSON.parse(text) : null) as T
}

export const hasWindow = () => store.customFrom > 0 && store.customTo > store.customFrom
const timeParams = (): Record<string, string> =>
  hasWindow() ? { from: String(Math.round(store.customFrom)), to: String(Math.round(store.customTo)) } : { range: store.range }

const get = <T>(path: string, params: Record<string, string> = {}) =>
  req<T>('GET', path, { ...timeParams(), ...params })

export function setWindow(fromMs: number, toMs: number) {
  store.customFrom = Math.round(fromMs)
  store.customTo = Math.round(toMs)
}
export function clearWindow() { store.customFrom = 0; store.customTo = 0 }

const arr = <T>(x: T[] | null | undefined): T[] => (Array.isArray(x) ? x : [])

export const SEV_TO_KEY: Record<string, string> = {
  crit: 'crit', critical: 'crit', compromised: 'crit', kill: 'crit',
  mid: 'mid', escalating: 'mid', high: 'mid', breakout_imminent: 'mid',
  warn: 'warn', warning: 'warn', suspicious: 'warn',
}
export const sevKey = (s: string) => SEV_TO_KEY[(s || '').toLowerCase()] || 'info'

export function isAlerting(w: Workload) { return w.state !== 'normal' }

function clientWorkloads(list: Workload[]) {
  const f = store.wlFilter
  const q = store.wlQ.trim().toLowerCase()
  return list.filter(w => {
    if (f === 'alerting' && !isAlerting(w)) return false
    if (f === 'quiet' && isAlerting(w)) return false
    if (f !== 'all' && f !== 'alerting' && f !== 'quiet' && w.node !== f) return false
    if (q && !`${w.pod}${w.comm}${w.rule}${w.namespace}`.toLowerCase().includes(q)) return false
    return true
  })
}

function clientEvents(list: AEvent[]) {
  const q = store.evQ.trim().toLowerCase()
  return list.filter(e => {
    if (store.evSev !== 'all' && sevKey(e.severity) !== store.evSev) return false
    if (q && !`${e.pod}${e.rule}${e.node}${e.event}${e.namespace}`.toLowerCase().includes(q)) return false
    return true
  })
}

export function pickChainPod(): string {
  if (store.chainPod) return store.chainPod
  // Prefer the most recent attacker that reached a terminal state. It lives in
  // the audit history (store.allEvents, newest first) and persists after the
  // pod is killed, so the panel stays on the real attack instead of flipping
  // every poll as killed pods vanish from the live workload set.
  const term = store.allEvents.find(e => e.enforced || e.severity === 'crit')
  if (term) return term.pod
  const w = store.allWorkloads
  const hit = w.find(x => x.state === 'compromised') || w.find(x => x.state === 'breakout_imminent')
    || w.find(x => x.state === 'escalating')
  return hit ? hit.pod : ''
}

let inflight = false
export async function refresh() {
  if (inflight || store.brushing) return
  inflight = true
  const wlParams = { filter: store.wlFilter === 'all' ? '' : store.wlFilter, q: store.wlQ.trim() }
  const evParams = { severity: store.evSev === 'all' ? '' : store.evSev, q: store.evQ.trim(), significant: store.evAll ? '' : '1' }
  const wlFiltered = !!(wlParams.filter || wlParams.q)
  const evFiltered = !!(evParams.severity || evParams.q || store.evAll)
  try {
    const [ov, wl, wlf, ev, evf, ru, nd, se, inc] = await Promise.allSettled([
      get<Overview>('/api/overview'),
      get<Workload[]>('/api/workloads'),
      wlFiltered ? get<Workload[]>('/api/workloads', wlParams) : Promise.resolve(null),
      get<AEvent[]>('/api/events', { significant: '1' }),
      evFiltered ? get<AEvent[]>('/api/events', evParams) : Promise.resolve(null),
      get<Rule[]>('/api/rules'),
      get<NodeInfo[]>('/api/nodes'),
      get<Settings>('/api/settings'),
      get<Incident[]>('/api/incidents'),
    ])
    const all = [ov, wl, wlf, ev, evf, ru, nd, se, inc]
    store.offline = all.some(r => r.status === 'rejected')
    if (ov.status === 'fulfilled') store.overview = ov.value
    if (wl.status === 'fulfilled') store.allWorkloads = arr(wl.value)
    if (ev.status === 'fulfilled') store.allEvents = arr(ev.value)
    if (ru.status === 'fulfilled') store.rules = arr(ru.value)
    if (nd.status === 'fulfilled') store.nodes = arr(nd.value)
    if (se.status === 'fulfilled') store.settings = se.value
    if (inc.status === 'fulfilled') store.incidents = arr(inc.value)
    store.workloads = clientWorkloads(wlf.status === 'fulfilled' && wlf.value ? arr(wlf.value) : store.allWorkloads)
    store.events = clientEvents(evf.status === 'fulfilled' && evf.value ? arr(evf.value) : store.allEvents)
    const pod = pickChainPod()
    if (pod) {
      try { store.chain = arr(await get<ChainStep[]>('/api/chain', { pod })) } catch { store.offline = true }
    } else {
      store.chain = []
    }
    await loadModalChain()
    store.loaded = true
  } finally {
    inflight = false
  }
}

export async function mute(pod: string) {
  await req('POST', '/api/mutes', {}, { pod })
  if (!store.muted.includes(pod)) store.muted.push(pod)
  await refresh()
}

export async function unmute(pod: string) {
  await req('DELETE', `/api/mutes/${encodeURIComponent(pod)}`)
  store.muted = store.muted.filter(p => p !== pod)
  await refresh()
}

async function loadModalChain() {
  const pod = store.chainModalPod
  if (!pod) return
  try {
    const c = arr(await get<ChainStep[]>('/api/chain', { pod }))
    if (store.chainModalPod === pod) store.modalChain = c
  } catch { store.offline = true }
}

export function openChainModal(pod: string) {
  store.chainModalPod = pod
  store.modalChain = []
  loadModalChain()
}
export function closeChainModal() { store.chainModalPod = ''; store.modalChain = [] }
export const inspectChain = openChainModal

export function startPolling() {
  const fromHash = location.hash.replace('#/', '') as Page
  if (['overview', 'workloads', 'events', 'incidents', 'rules', 'nodes', 'settings'].includes(fromHash)) store.page = fromHash
  watch(() => store.page, p => { location.hash = '#/' + p; window.scrollTo(0, 0) })
  watch(() => [store.range, store.customFrom, store.customTo, store.evAll, store.wlFilter, store.wlQ, store.evSev, store.evQ, store.chainPod], () => refresh())
  refresh()
  setInterval(refresh, POLL_MS)
}

/* formatting helpers */
export function toMs(t: number): number {
  if (t > 1e17) return t / 1e6
  if (t > 1e14) return t / 1e3
  if (t > 1e11) return t
  return t * 1000
}
export const pad = (n: number) => String(n).padStart(2, '0')
export function clock(ms: number) {
  const d = new Date(ms)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
export const clockNs = (ns: number) => clock(ns / 1e6)
export function fmtNum(n: number) {
  if (n == null || isNaN(n)) return '0'
  return Math.abs(n) >= 100 ? Math.round(n).toLocaleString() : (Math.round(n * 10) / 10).toLocaleString()
}
export function fmtWindow(ns: number) {
  const s = ns / 1e9
  if (s >= 3600) return `${+(s / 3600).toFixed(1)}h`
  if (s >= 60) return `${+(s / 60).toFixed(1)}m`
  if (s >= 1) return `${+s.toFixed(1)}s`
  return `${Math.round(ns / 1e6)}ms`
}
export function fmtBytes(b: number) {
  if (b >= 1048576) return `${+(b / 1048576).toFixed(1)} MiB`
  return `${+(b / 1024).toFixed(1)} KiB`
}
export const isKill = (a: string) => (a || '').toLowerCase().includes('kill')
export function nodeOk(s: string) { return ['ready', 'healthy', 'up', 'ok', 'online'].includes((s || '').toLowerCase()) }
