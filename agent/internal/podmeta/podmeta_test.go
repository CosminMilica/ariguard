package podmeta

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var (
	idA = strings.Repeat("a1", 32)
	idB = strings.Repeat("b2", 32)
	idC = strings.Repeat("c3", 32)
)

func TestContainerID(t *testing.T) {
	cases := map[string]string{
		"/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + idA + ".scope": idA,
		"/system.slice/docker-" + idA + ".scope":                               idA,
		"/kubepods.slice/kubepods-besteffort.slice/crio-" + idA + ".scope":     idA,
		"/kubepods/besteffort/pod1234/" + idA:                                  idA,
		"/kubepods/besteffort/pod1234":                                         "",
		"/user.slice/user-1000.slice/session-3.scope":                          "",
		"/":                                     "",
		"/docker-" + idA[:63] + ".scope":        "",
		"/docker-" + strings.ToUpper(idA) + "x": "",
	}
	for path, want := range cases {
		if got := ContainerID(path); got != want {
			t.Errorf("ContainerID(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestStripRuntime(t *testing.T) {
	for in, want := range map[string]string{
		"containerd://" + idA: idA,
		"cri-o://" + idA:      idA,
		"docker://" + idA:     idA,
		idA:                   idA,
		"":                    "",
	} {
		if got := stripRuntime(in); got != want {
			t.Errorf("stripRuntime(%q) = %q, want %q", in, got, want)
		}
	}
}

func mkdir(t *testing.T, root, rel string) uint64 {
	t.Helper()
	dir := filepath.Join(root, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	ino, ok := inode(fi)
	if !ok {
		t.Skip("no inode numbers on this platform")
	}
	return ino
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newResolver(t *testing.T, root string, objs ...runtime.Object) (*Resolver, *fake.Clientset, *clock) {
	t.Helper()
	client := fake.NewClientset(objs...)
	r := New(root, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := &clock{t: time.Unix(1000, 0)}
	r.now = c.now
	return r, client, c
}

func TestWalk(t *testing.T) {
	root := t.TempDir()
	rel := "kubepods.slice/kubepods-pod1.slice/cri-containerd-" + idA + ".scope"
	ino := mkdir(t, root, rel)
	rootIno := mkdir(t, root, "")
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r, _, _ := newResolver(t, root)
	r.walk()
	if got := r.paths[ino]; got != "/"+rel {
		t.Errorf("paths[%d] = %q, want %q", ino, got, "/"+rel)
	}
	if got := r.paths[rootIno]; got != "/" {
		t.Errorf("root path = %q, want /", got)
	}
}

func TestIsPod(t *testing.T) {
	root := t.TempDir()
	inoPod := mkdir(t, root, "kubepods.slice/kubepods-pod1.slice/cri-containerd-"+idA+".scope")
	inoRuntime := mkdir(t, root, "system.slice/containerd.service")
	r, _, _ := newResolver(t, root)
	if !r.IsPod(inoPod) {
		t.Errorf("IsPod(pod container cgroup) = false, want true")
	}
	if r.IsPod(inoRuntime) {
		t.Errorf("IsPod(containerd.service) = true, want false")
	}
	if r.IsPod(1 << 62) {
		t.Errorf("IsPod(unknown cgroup) = true, want false")
	}
}

func pod(ns, name string, statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     corev1.PodStatus{ContainerStatuses: statuses},
	}
}

func TestLookup(t *testing.T) {
	root := t.TempDir()
	inoA := mkdir(t, root, "kubepods.slice/kubepods-pod1.slice/cri-containerd-"+idA+".scope")
	inoHost := mkdir(t, root, "system.slice/sshd.service")

	p := pod("statewall-eval", "container-escape",
		corev1.ContainerStatus{Name: "attacker", ContainerID: "containerd://" + idA})
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "containerd://" + idB}}
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", ContainerID: "containerd://" + idC}}
	r, client, clk := newResolver(t, root, p)
	lists := 0
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists++
		return false, nil, nil
	})
	ctx := context.Background()

	want := Info{Namespace: "statewall-eval", Pod: "container-escape", Container: "attacker"}
	if got := r.Lookup(ctx, inoA); got != want {
		t.Fatalf("Lookup = %+v, want %+v", got, want)
	}
	if got := r.Lookup(ctx, inoHost); got != (Info{}) {
		t.Errorf("host cgroup = %+v, want empty", got)
	}
	if r.containers[idB].Container != "init" || r.containers[idC].Container != "debug" {
		t.Errorf("init/ephemeral containers not indexed: %+v", r.containers)
	}

	// A new container appears: misses are rate limited, then picked up.
	inoB := mkdir(t, root, "kubepods.slice/kubepods-pod2.slice/cri-containerd-"+idB+".scope")
	if got := r.Lookup(ctx, inoB); got != (Info{}) {
		t.Errorf("Lookup before the refresh interval = %+v, want empty", got)
	}
	clk.t = clk.t.Add(refreshInterval)
	if got := r.Lookup(ctx, inoB); got.Container != "init" {
		t.Errorf("Lookup after refresh = %+v, want the init container", got)
	}
	if lists != 1 {
		t.Errorf("pod lists = %d, want 1 (cached)", lists)
	}

	if got := r.Lookup(ctx, 1<<62); got != (Info{}) {
		t.Errorf("unknown cgroup = %+v, want empty", got)
	}
}

func TestLookupPodRefresh(t *testing.T) {
	root := t.TempDir()
	ino := mkdir(t, root, "kubepods/besteffort/pod1/"+idA)
	r, client, clk := newResolver(t, root)
	ctx := context.Background()
	if got := r.Lookup(ctx, ino); got != (Info{}) {
		t.Fatalf("Lookup before the pod exists = %+v", got)
	}
	_, err := client.CoreV1().Pods("ns").Create(ctx,
		pod("ns", "late", corev1.ContainerStatus{Name: "c", ContainerID: "cri-o://" + idA}), metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Lookup(ctx, ino); got != (Info{}) {
		t.Errorf("Lookup within the refresh interval = %+v, want empty", got)
	}
	clk.t = clk.t.Add(refreshInterval)
	if got := r.Lookup(ctx, ino); got != (Info{Namespace: "ns", Pod: "late", Container: "c"}) {
		t.Errorf("Lookup after refresh = %+v", got)
	}
}

func TestLookupWithoutClient(t *testing.T) {
	root := t.TempDir()
	ino := mkdir(t, root, "docker-"+idA+".scope")
	r := New(root, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := r.Lookup(context.Background(), ino); got != (Info{}) {
		t.Errorf("Lookup = %+v, want empty", got)
	}
}

func TestNewClient(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "kubeconfig")
	cfg := "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster: {server: \"https://127.0.0.1:1\"}\n" +
		"contexts:\n- name: x\n  context: {cluster: c, user: u}\ncurrent-context: x\nusers:\n- name: u\n  user: {}\n"
	if err := os.WriteFile(good, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	cases := []struct {
		name       string
		kubeconfig string
		wantErr    bool
	}{
		{"valid kubeconfig", good, false},
		{"missing kubeconfig", filepath.Join(dir, "nope"), true},
		{"malformed kubeconfig", bad, true},
		{"not in cluster", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(tc.kubeconfig)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewClient err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && client == nil {
				t.Error("nil client")
			}
		})
	}
}

func TestWalkMissingRoot(t *testing.T) {
	r, _, _ := newResolver(t, filepath.Join(t.TempDir(), "absent"))
	r.walk()
	if len(r.paths) != 0 {
		t.Errorf("paths = %v, want empty", r.paths)
	}
}

func TestListError(t *testing.T) {
	root := t.TempDir()
	ino := mkdir(t, root, "docker-"+idA+".scope")
	r, client, _ := newResolver(t, root)
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	if got := r.Lookup(context.Background(), ino); got != (Info{}) {
		t.Errorf("Lookup = %+v, want empty", got)
	}
	if r.containers != nil {
		t.Errorf("containers = %v, want untouched", r.containers)
	}
}

func TestCgroupPath(t *testing.T) {
	cases := []struct{ root, path, want string }{
		{"/sys/fs/cgroup", "/sys/fs/cgroup", "/"},
		{"/sys/fs/cgroup", "/sys/fs/cgroup/a/b", "/a/b"},
		{"rel", "/abs", "/"},
	}
	for _, tc := range cases {
		if got := cgroupPath(tc.root, tc.path); got != tc.want {
			t.Errorf("cgroupPath(%q, %q) = %q, want %q", tc.root, tc.path, got, tc.want)
		}
	}
}

func TestPodCgroups(t *testing.T) {
	root := t.TempDir()
	pod := mkdir(t, root, "kubepods.slice/kubepods-pod1.slice/cri-containerd-"+idA+".scope")
	mkdir(t, root, "system.slice/docker-"+idB+".scope")
	mkdir(t, root, "kubepods.slice/kubepods-pod1.slice")
	r, _, _ := newResolver(t, root)
	got := r.PodCgroups()
	if len(got) != 1 || got[0] != pod {
		t.Fatalf("PodCgroups = %v, want [%d]", got, pod)
	}
}
