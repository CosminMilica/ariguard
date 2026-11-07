package api

import (
	"net/http"
	"sort"
)

// edge is one observed network pivot: a source pod connecting to a destination pod, resolved from
// the connect destination IP (F2). Unlike the actor-spread view (/api/lateral), these are real
// pod→pod connections the agent observed, not image-correlation inference.
type edge struct {
	SrcNamespace string   `json:"src_namespace"`
	SrcPod       string   `json:"src_pod"`
	SrcOwner     string   `json:"src_owner"` // source workload (e.g. Deployment/frontend)
	DstNamespace string   `json:"dst_namespace"`
	DstPod       string   `json:"dst_pod"`
	CrossNs      bool     `json:"cross_ns"` // src and dst in different namespaces (true lateral reach)
	Count        int64    `json:"count"`    // connect events on this edge
	Ports        []int64  `json:"ports"`
	Rules        []string `json:"rules"`
	FirstNS      int64    `json:"first_ts_ns"`
	LastNS       int64    `json:"last_ts_ns"`
}

// edges reconstructs observed pod→pod network pivots within the window from connect events whose
// destination IP resolved to a pod. Cross-namespace edges (real lateral reach) sort first.
func (a *API) edges(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT namespace, pod, owner, dst_ns, dst_pod, dst_port, rule, ts_ns
		FROM audit_events
		WHERE dst_pod != '' AND pod != '' AND ts_ns >= ? AND ts_ns <= ?
		ORDER BY ts_ns LIMIT 50000`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()

	type agg struct {
		edge
		ports map[int64]bool
		rules map[string]bool
	}
	seen := map[string]*agg{}
	order := []string{}
	for rows.Next() {
		var srcNs, srcPod, srcOwner, dstNs, dstPod, rule string
		var port, ts int64
		if err := rows.Scan(&srcNs, &srcPod, &srcOwner, &dstNs, &dstPod, &port, &rule, &ts); err != nil {
			fail(w, err)
			return
		}
		if srcNs == dstNs && srcPod == dstPod { // a pod connecting to itself is not a pivot
			continue
		}
		key := srcNs + "\x00" + srcPod + "\x00" + dstNs + "\x00" + dstPod
		ac := seen[key]
		if ac == nil {
			ac = &agg{
				edge:  edge{SrcNamespace: srcNs, SrcPod: srcPod, SrcOwner: srcOwner, DstNamespace: dstNs, DstPod: dstPod, CrossNs: srcNs != dstNs, FirstNS: ts},
				ports: map[int64]bool{}, rules: map[string]bool{},
			}
			seen[key] = ac
			order = append(order, key)
		}
		ac.Count++
		if ts < ac.FirstNS {
			ac.FirstNS = ts
		}
		if ts > ac.LastNS {
			ac.LastNS = ts
		}
		if port != 0 {
			ac.ports[port] = true
		}
		if rule != "" {
			ac.rules[rule] = true
		}
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	out := make([]edge, 0, len(order))
	for _, key := range order {
		ac := seen[key]
		ac.Ports = int64KeysSorted(ac.ports)
		ac.Rules = keysSorted(ac.rules)
		out = append(out, ac.edge)
	}
	// cross-namespace pivots first (real lateral reach), then busiest edges.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CrossNs != out[j].CrossNs {
			return out[i].CrossNs
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastNS > out[j].LastNS
	})
	writeJSON(w, out)
}

func int64KeysSorted(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
