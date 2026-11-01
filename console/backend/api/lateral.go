package api

import (
	"net/http"
	"sort"
)

// actorTrail is one actor (container image digest) and the ordered namespaces it reached.
type actorTrail struct {
	ImageID    string   `json:"image_id"`
	Image      string   `json:"image"`
	Path       []string `json:"path"` // distinct namespaces in first-seen order
	Hops       int      `json:"hops"` // len(path)-1 (0 = no lateral movement)
	Namespaces int      `json:"namespaces"`
	Pods       int64    `json:"pods"`
	Incidents  int64    `json:"incidents"`
	Killed     int64    `json:"killed"`
	Blocked    int64    `json:"blocked"`
	Rules      []string `json:"rules"`
	FirstNS    int64    `json:"first_ts_ns"`
	LastNS     int64    `json:"last_ts_ns"`
}

type lateralOut struct {
	Actors     []actorTrail `json:"actors"`
	Namespaces []string     `json:"namespaces"` // every namespace seen, for the filter dropdown
}

// lateral reconstructs each actor's movement as an ordered namespace trail. An actor is a
// container image digest; its path is the distinct namespaces it reached, earliest first.
// Actors that moved (hops >= 1) sort first. The frontend filters by actor/namespace and draws
// the focused path, so this stays legible with many incidents.
func (a *API) lateral(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT image_id, image, namespace, pod, rule, killed, blocked, first_ns
		FROM (`+incidentGroupsSQL+`)
		WHERE image_id != '' AND namespace != ''
		ORDER BY image_id, first_ns`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()

	type agg struct {
		image     string
		path      []string
		seenNS    map[string]bool
		pods      map[string]bool
		rules     map[string]bool
		incidents int64
		killed    int64
		blocked   int64
		firstNS   int64
		lastNS    int64
	}
	actors := map[string]*agg{}
	order := []string{} // image_id order of first appearance
	allNS := map[string]bool{}

	for rows.Next() {
		var imageID, image, ns, pod, rule string
		var killed, blocked, firstNS int64
		if err := rows.Scan(&imageID, &image, &ns, &pod, &rule, &killed, &blocked, &firstNS); err != nil {
			fail(w, err)
			return
		}
		allNS[ns] = true
		ac := actors[imageID]
		if ac == nil {
			ac = &agg{image: image, seenNS: map[string]bool{}, pods: map[string]bool{}, rules: map[string]bool{}, firstNS: firstNS}
			actors[imageID] = ac
			order = append(order, imageID)
		}
		ac.incidents++
		ac.killed += killed
		ac.blocked += blocked
		ac.pods[pod] = true
		if rule != "" {
			ac.rules[rule] = true
		}
		if firstNS < ac.firstNS {
			ac.firstNS = firstNS
		}
		if firstNS > ac.lastNS {
			ac.lastNS = firstNS
		}
		if !ac.seenNS[ns] { // first time this actor reaches this namespace -> extend the path
			ac.seenNS[ns] = true
			ac.path = append(ac.path, ns)
		}
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	out := lateralOut{Actors: []actorTrail{}, Namespaces: []string{}}
	for _, id := range order {
		ac := actors[id]
		out.Actors = append(out.Actors, actorTrail{
			ImageID: id, Image: ac.image, Path: ac.path, Hops: len(ac.path) - 1,
			Namespaces: len(ac.path), Pods: int64(len(ac.pods)), Incidents: ac.incidents,
			Killed: ac.killed, Blocked: ac.blocked, Rules: keysSorted(ac.rules),
			FirstNS: ac.firstNS, LastNS: ac.lastNS,
		})
	}
	// movers first (most hops), then widest spread, then most incidents.
	sort.Slice(out.Actors, func(i, j int) bool {
		if out.Actors[i].Hops != out.Actors[j].Hops {
			return out.Actors[i].Hops > out.Actors[j].Hops
		}
		if out.Actors[i].Pods != out.Actors[j].Pods {
			return out.Actors[i].Pods > out.Actors[j].Pods
		}
		return out.Actors[i].Incidents > out.Actors[j].Incidents
	})
	for ns := range allNS {
		out.Namespaces = append(out.Namespaces, ns)
	}
	sort.Strings(out.Namespaces)
	writeJSON(w, out)
}

func keysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
