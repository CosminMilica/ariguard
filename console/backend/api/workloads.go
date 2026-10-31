package api

import "net/http"

type workload struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Node      string `json:"node"`
	Comm      string `json:"comm"`
	Rule      string `json:"rule"`
	State     string `json:"state"`
	Action    string `json:"action"`
}

func (a *API) workloads(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	q := r.URL.Query().Get("q")

	query := `SELECT pod,namespace,node,comm,rule,state,action FROM workloads
		WHERE pod NOT IN (SELECT pod FROM mutes)`
	var args []any
	switch filter {
	case "", "all":
	case "alerting":
		query += ` AND state != 'normal'`
	case "quiet":
		query += ` AND state = 'normal'`
	default:
		query += ` AND node = ?`
		args = append(args, filter)
	}
	if q != "" {
		query += ` AND (pod LIKE ? OR namespace LIKE ? OR node LIKE ? OR comm LIKE ? OR rule LIKE ?)`
		l := like(q)
		args = append(args, l, l, l, l, l)
	}
	query += ` ORDER BY namespace, pod, rule`

	rows, err := a.DB.Query(query, args...)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []workload{}
	for rows.Next() {
		var x workload
		if err := rows.Scan(&x.Pod, &x.Namespace, &x.Node, &x.Comm, &x.Rule, &x.State, &x.Action); err != nil {
			fail(w, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, out)
}
