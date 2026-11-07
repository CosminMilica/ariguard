CREATE TABLE IF NOT EXISTS nodes (
  node TEXT PRIMARY KEY,
  kernel TEXT NOT NULL DEFAULT '',
  enforce INTEGER NOT NULL DEFAULT 0,
  hooks_attached INTEGER NOT NULL DEFAULT 0,
  hooks_total INTEGER NOT NULL DEFAULT 0,
  audit_ring_bytes INTEGER NOT NULL DEFAULT 0,
  metrics_addr TEXT NOT NULL DEFAULT '',
  bpf_map_bytes INTEGER NOT NULL DEFAULT 0, -- constant pre-allocated BPF map budget
  last_seen INTEGER NOT NULL DEFAULT 0 -- unix ms
);

CREATE TABLE IF NOT EXISTS rules (
  node TEXT NOT NULL,
  name TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  num_states INTEGER NOT NULL DEFAULT 0,
  window_ns INTEGER NOT NULL DEFAULT 0,
  terminal_action TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}', -- JSON: {states,events,terminal_from,transitions}
  PRIMARY KEY (node, name)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ns INTEGER NOT NULL,
  node TEXT NOT NULL DEFAULT '',
  pod TEXT NOT NULL DEFAULT '',
  namespace TEXT NOT NULL DEFAULT '',
  comm TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL DEFAULT '',
  from_state TEXT NOT NULL DEFAULT '',
  to_state TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  enforced INTEGER NOT NULL DEFAULT 0,
  cgroup_id INTEGER NOT NULL DEFAULT 0,
  pid INTEGER NOT NULL DEFAULT 0,
  ppid INTEGER NOT NULL DEFAULT 0,
  hook TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  image_id TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  app TEXT NOT NULL DEFAULT '',
  dst_ip TEXT NOT NULL DEFAULT '',
  dst_port INTEGER NOT NULL DEFAULT 0,
  dst_pod TEXT NOT NULL DEFAULT '',
  dst_ns TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  argv TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_ns);
CREATE INDEX IF NOT EXISTS idx_audit_pod ON audit_events(pod);

CREATE TABLE IF NOT EXISTS metric_samples (
  ts INTEGER NOT NULL, -- unix ms
  node TEXT NOT NULL,
  events INTEGER NOT NULL DEFAULT 0,
  kills INTEGER NOT NULL DEFAULT 0,
  denies INTEGER NOT NULL DEFAULT 0,
  audit_dropped INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_samples_node_ts ON metric_samples(node, ts);

CREATE TABLE IF NOT EXISTS workloads (
  node TEXT NOT NULL,
  pod TEXT NOT NULL,
  namespace TEXT NOT NULL DEFAULT '',
  comm TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'normal',
  action TEXT NOT NULL DEFAULT '',
  updated INTEGER NOT NULL DEFAULT 0, -- unix ms
  PRIMARY KEY (node, pod, rule)
);

CREATE TABLE IF NOT EXISTS program_stats (
  node TEXT NOT NULL,
  program TEXT NOT NULL,
  runs INTEGER NOT NULL DEFAULT 0,
  run_time_ns INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0, -- unix ms
  PRIMARY KEY (node, program)
);

CREATE TABLE IF NOT EXISTS mutes (
  pod TEXT PRIMARY KEY
);

-- Observe-only namespaces: the agent detects but never kills or quarantines pods here, yet their
-- events still count as attack traffic (unlike muted pods). Lets a discovery honeypot run alongside
-- an enforcing fleet so its mined rules both appear and promote.
CREATE TABLE IF NOT EXISTS observe_namespaces (
  namespace TEXT PRIMARY KEY
);

-- Learn-mode namespaces (F11): the agent emits full-syscall traces from pods here to the console, so
-- the rule-generation loop mines novel chains from real production traffic and gates them against a
-- real benign baseline. Opt-in per namespace (empty = no emit, zero overhead); detection is
-- unaffected, this only adds the raw trace stream.
CREATE TABLE IF NOT EXISTS learn_namespaces (
  namespace TEXT PRIMARY KEY
);

-- Operator key/value settings. Holds the desired fleet enforcement mode ("enforce_mode" = enforce |
-- detect): agents poll it and hot-swap the current bundle under the new mode, no restart. Absent =
-- agents keep their launch-flag mode.
CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
  node TEXT NOT NULL,
  namespace TEXT NOT NULL DEFAULT '',
  pod TEXT NOT NULL,
  rule TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT '',
  ts_ns INTEGER NOT NULL DEFAULT 0,
  released INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node, namespace, pod)
);
CREATE INDEX IF NOT EXISTS idx_quarantine_pod ON quarantine(pod);

-- Honeypot-captured full-syscall traces (F11 discovery): a honeypot's strace output, parsed into
-- attack-labeled traces and POSTed here; the rule-generation loop pulls them to mine new chains.
CREATE TABLE IF NOT EXISTS honeypot_traces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ns INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT 'attack',
  source TEXT NOT NULL DEFAULT '',
  hash TEXT NOT NULL UNIQUE, -- content hash; dedups a re-posting sidecar
  events TEXT NOT NULL DEFAULT '[]' -- the original trace JSON object (one mining run)
);

-- The control plane's current policy bundle (F7): one row, pushed by the rule pipeline and polled
-- by agents so rules distribute to the fleet without rebuilding the agent image.
CREATE TABLE IF NOT EXISTS policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  bundle BLOB NOT NULL,
  ts_ns INTEGER NOT NULL DEFAULT 0,
  -- Detached ed25519 signature of the bundle (base64), set by the signing pusher (C2). Served back in
  -- the X-Policy-Signature header so agents can verify authenticity before loading it into the kernel.
  signature TEXT NOT NULL DEFAULT ''
);
