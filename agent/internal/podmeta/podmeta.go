// Package podmeta resolves a cgroup id to the Kubernetes pod and container running in it (E12).
package podmeta

import (
	"context"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultCgroupRoot is the cgroup v2 mount point.
const DefaultCgroupRoot = "/sys/fs/cgroup"

const (
	refreshInterval = 2 * time.Second
	listTimeout     = time.Second
)

// Info names a container; fields are empty when unknown.
type Info struct {
	Namespace string
	Pod       string
	Container string
}

// Resolver maps cgroup ids to pod metadata, caching both cgroup paths and pods.
type Resolver struct {
	root   string
	client kubernetes.Interface
	log    *slog.Logger
	now    func() time.Time

	mu         sync.Mutex
	paths      map[uint64]string
	walkedAt   time.Time
	containers map[string]Info
	listedAt   time.Time
}

// New returns a resolver over the cgroup tree at root; client may be nil (no pod names).
func New(root string, client kubernetes.Interface, log *slog.Logger) *Resolver {
	return &Resolver{root: root, client: client, log: log, now: time.Now}
}

// NewClient builds a clientset from kubeconfig, or from the in-cluster config when it is empty.
func NewClient(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	cfg.Timeout = listTimeout
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Lookup returns the pod metadata of the cgroup, or zero Info when unknown.
// It blocks for at most one cgroup walk and one bounded pod list.
func (r *Resolver) Lookup(ctx context.Context, cgroupID uint64) Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	path, ok := r.paths[cgroupID]
	if !ok && r.due(r.walkedAt) {
		r.walk()
		path, ok = r.paths[cgroupID]
	}
	if !ok {
		return Info{}
	}
	id := ContainerID(path)
	if id == "" || r.client == nil {
		return Info{}
	}
	info, ok := r.containers[id]
	if !ok && r.due(r.listedAt) {
		r.list(ctx)
		info = r.containers[id]
	}
	return info
}

// IsPod reports whether cgroupID is a Kubernetes pod container cgroup. It is
// resolved from the cgroup tree walk alone (no API call), so it does not depend
// on pod-name resolution being ready.
func (r *Resolver) IsPod(cgroupID uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	path, ok := r.paths[cgroupID]
	if !ok && r.due(r.walkedAt) {
		r.walk()
		path, ok = r.paths[cgroupID]
	}
	return ok && IsPodCgroup(path)
}

func (r *Resolver) due(last time.Time) bool {
	return last.IsZero() || r.now().Sub(last) >= refreshInterval
}

func (r *Resolver) walk() {
	r.walkedAt = r.now()
	paths := make(map[uint64]string, len(r.paths))
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == r.root {
				r.log.Warn("walk cgroup tree", "root", r.root, "err", err)
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if ino, ok := inode(fi); ok {
			paths[ino] = cgroupPath(r.root, path)
		}
		return nil
	})
	r.paths = paths
}

func (r *Resolver) list(ctx context.Context) {
	r.listedAt = r.now()
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	pods, err := r.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		r.log.Warn("list pods", "err", err)
		return
	}
	containers := make(map[string]Info)
	for _, p := range pods.Items {
		for _, statuses := range [][]corev1.ContainerStatus{
			p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses,
		} {
			for _, s := range statuses {
				if id := stripRuntime(s.ContainerID); id != "" {
					containers[id] = Info{Namespace: p.Namespace, Pod: p.Name, Container: s.Name}
				}
			}
		}
	}
	r.containers = containers
}

func cgroupPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

// ContainerID extracts the 64-hex container id from the last element of a cgroup path:
// cri-containerd-<id>.scope, docker-<id>.scope, crio-<id>.scope or a bare <id>.
func ContainerID(path string) string {
	name := strings.TrimSuffix(path[strings.LastIndexByte(path, '/')+1:], ".scope")
	if i := strings.LastIndexByte(name, '-'); i >= 0 {
		name = name[i+1:]
	}
	if !isContainerID(name) {
		return ""
	}
	return name
}

func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// stripRuntime turns "containerd://<id>" into "<id>".
func stripRuntime(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

// PodCgroups walks the cgroup tree and returns the ids of all pod container cgroups.
func (r *Resolver) PodCgroups() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.walk()
	ids := make([]uint64, 0, len(r.paths))
	for id, path := range r.paths {
		if IsPodCgroup(path) {
			ids = append(ids, id)
		}
	}
	return ids
}

// IsPodCgroup reports whether path is a Kubernetes container cgroup.
func IsPodCgroup(path string) bool {
	return strings.Contains(path, "kubepods") && ContainerID(path) != ""
}
