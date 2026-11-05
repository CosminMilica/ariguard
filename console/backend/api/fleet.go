package api

import (
	"net/http"
	"sort"
)

// nodeHit is one node's share of a cross-node threat.
type nodeHit struct {
	Node      string `json:"node"`
	Incidents int64  `json:"incidents"`
	FirstNS   int64  `json:"first_ts_ns"`
	LastNS    int64  `json:"last_ts_ns"`
}

// fleetThreat is one threat signature correlated across >= 2 nodes: the same compromised image
// (an actor) or, when no image is known, the same rule firing fleet-wide. This is the coordinated /
// worm signal a single-node incident view misses.
type fleetThreat struct {
	Kind      string    `json:"kind"` // "actor" (by image) | "rule"
	Signature string    `json:"signature"`
	Image     string    `json:"image,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	NodeCount int64     `json:"node_count"`
	Incidents int64     `json:"incidents"`
	Killed    int64     `json:"killed"`
	Blocked   int64     `json:"blocked"`
	Detected  int64     `json:"detected"`
	FirstNS   int64     `json:"first_ts_ns"`
	LastNS    int64     `json:"last_ts_ns"`
	Spreading bool      `json:"spreading"` // reached new nodes after it first appeared
	Nodes     []nodeHit `json:"nodes"`
}

// fleet correlates incident groups into cross-node threats: grouped by compromised image (actor) or,
// lacking one, by rule, keeping only signatures seen on two or more nodes. Widest spread first.
func (a *API) fleet(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT node, rule, image_id, image, killed, blocked, first_ns, last_ns
		FROM (`+incidentGroupsSQL+`)`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()

	type agg struct {
		t     *fleetThreat
		nodes map[string]*nodeHit
	}
	byKey := map[string]*agg{}
	for rows.Next() {
		var node, rule, imageID, image string
		var killed, blocked, first, last int64
		if err := rows.Scan(&node, &rule, &imageID, &image, &killed, &blocked, &first, &last); err != nil {
			fail(w, err)
			return
		}
		kind, key, sig := "rule", "rule:"+rule, rule
		if imageID != "" {
			kind, key, sig = "actor", "img:"+imageID, image
		}
		g := byKey[key]
		if g == nil {
			g = &agg{t: &fleetThreat{Kind: kind, Signature: sig, Rule: rule}, nodes: map[string]*nodeHit{}}
			if kind == "actor" {
				g.t.Image = image
			} else {
				g.t.Rule = rule
			}
			byKey[key] = g
		}
		t := g.t
		t.Incidents++
		switch {
		case killed == 1:
			t.Killed++
		case blocked == 1:
			t.Blocked++
		default:
			t.Detected++
		}
		if t.FirstNS == 0 || first < t.FirstNS {
			t.FirstNS = first
		}
		if last > t.LastNS {
			t.LastNS = last
		}
		n := g.nodes[node]
		if n == nil {
			n = &nodeHit{Node: node}
			g.nodes[node] = n
		}
		n.Incidents++
		if n.FirstNS == 0 || first < n.FirstNS {
			n.FirstNS = first
		}
		if last > n.LastNS {
			n.LastNS = last
		}
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	out := []fleetThreat{}
	for _, g := range byKey {
		if len(g.nodes) < 2 { // single-node incidents are not a fleet correlation
			continue
		}
		t := g.t
		for _, n := range g.nodes {
			t.Nodes = append(t.Nodes, *n)
		}
		// Earliest node first; spreading = a node was first hit after the signature first appeared.
		sort.Slice(t.Nodes, func(i, j int) bool { return t.Nodes[i].FirstNS < t.Nodes[j].FirstNS })
		t.NodeCount = int64(len(t.Nodes))
		t.Spreading = t.Nodes[len(t.Nodes)-1].FirstNS > t.Nodes[0].FirstNS
		out = append(out, *t)
	}
	// Widest spread first, then busiest, then most recent.
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeCount != out[j].NodeCount {
			return out[i].NodeCount > out[j].NodeCount
		}
		if out[i].Incidents != out[j].Incidents {
			return out[i].Incidents > out[j].Incidents
		}
		return out[i].LastNS > out[j].LastNS
	})
	writeJSON(w, out)
}
