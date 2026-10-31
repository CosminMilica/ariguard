CREATE TABLE IF NOT EXISTS nodes (
  node TEXT PRIMARY KEY,
  kernel TEXT NOT NULL DEFAULT '',
  enforce INTEGER NOT NULL DEFAULT 0,
  hooks_attached INTEGER NOT NULL DEFAULT 0,
  hooks_total INTEGER NOT NULL DEFAULT 0,
  audit_ring_bytes INTEGER NOT NULL DEFAULT 0,
  metrics_addr TEXT NOT NULL DEFAULT '',
  last_seen INTEGER NOT NULL DEFAULT 0 -- unix ms
);

CREATE TABLE IF NOT EXISTS rules (
  node TEXT NOT NULL,
  name TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  num_states INTEGER NOT NULL DEFAULT 0,
  window_ns INTEGER NOT NULL DEFAULT 0,
  terminal_action TEXT NOT NULL DEFAULT '',
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
  cgroup_id INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS mutes (
  pod TEXT PRIMARY KEY
);
