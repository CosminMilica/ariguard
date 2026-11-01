package api

import (
	"net/http"
	"sort"
)

type latNode struct {
	Namespace string `json:"namespace"`
	Incidents int64  `json:"incidents"`
	Pods      int64  `json:"pods"`
}

type latEdge struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Count  int64    `json:"count"`
	Images []string `json:"images"`
}

type lateralOut struct {
	Nodes []latNode `json:"nodes"`
	Edges []latEdge `json:"edges"`
}

// lateral reconstructs attacker movement across namespaces: for each actor (container image
// digest), the time-ordered sequence of namespaces it reached becomes directed edges A->B.
// Nodes are namespaces that had incidents; edges are the spread between them.
func (a *API) lateral(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT image_id, namespace, pod, first_ns
		FROM (`+incidentGroupsSQL+`)
		WHERE image_id != '' AND namespace != ''
		ORDER BY image_id, first_ns`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()

	type nodeAgg struct {
		incidents int64
		pods      map[string]bool
	}
	nodes := map[string]*nodeAgg{}
	type edgeAgg struct {
		count  int64
		images map[string]bool
	}
	edges := map[[2]string]*edgeAgg{}

	var curImage, lastNS string
	addEdge := func(from, to, image string) {
		if from == "" || from == to {
			return
		}
		k := [2]string{from, to}
		e := edges[k]
		if e == nil {
			e = &edgeAgg{images: map[string]bool{}}
			edges[k] = e
		}
		e.count++
		e.images[image] = true
	}
	for rows.Next() {
		var imageID, ns, pod string
		var firstNS int64
		if err := rows.Scan(&imageID, &ns, &pod, &firstNS); err != nil {
			fail(w, err)
			return
		}
		n := nodes[ns]
		if n == nil {
			n = &nodeAgg{pods: map[string]bool{}}
			nodes[ns] = n
		}
		n.incidents++
		n.pods[pod] = true

		if imageID != curImage { // new actor: reset the movement trail
			curImage, lastNS = imageID, ""
		}
		if ns != lastNS { // collapse consecutive repeats; an actor changing namespace is a hop
			addEdge(lastNS, ns, imageID)
			lastNS = ns
		}
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	out := lateralOut{Nodes: []latNode{}, Edges: []latEdge{}}
	for ns, n := range nodes {
		out.Nodes = append(out.Nodes, latNode{Namespace: ns, Incidents: n.incidents, Pods: int64(len(n.pods))})
	}
	sort.Slice(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Incidents != out.Nodes[j].Incidents {
			return out.Nodes[i].Incidents > out.Nodes[j].Incidents
		}
		return out.Nodes[i].Namespace < out.Nodes[j].Namespace
	})
	for k, e := range edges {
		imgs := make([]string, 0, len(e.images))
		for im := range e.images {
			imgs = append(imgs, im)
		}
		sort.Strings(imgs)
		out.Edges = append(out.Edges, latEdge{From: k[0], To: k[1], Count: e.count, Images: imgs})
	}
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].Count != out.Edges[j].Count {
			return out.Edges[i].Count > out.Edges[j].Count
		}
		if out.Edges[i].From != out.Edges[j].From {
			return out.Edges[i].From < out.Edges[j].From
		}
		return out.Edges[i].To < out.Edges[j].To
	})
	writeJSON(w, out)
}
