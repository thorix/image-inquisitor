package kubernetes

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	appsv1c "k8s.io/client-go/kubernetes/typed/apps/v1"
	batchv1c "k8s.io/client-go/kubernetes/typed/batch/v1"
	corev1c "k8s.io/client-go/kubernetes/typed/core/v1"
)

// errBlock makes a List wait for its context to end.
var errBlock = fmt.Errorf("block")

// fakeCS is a hand-written clientset stub; only List is implemented.
type fakeCS struct {
	kubernetes.Interface
	namespaces []string
	// fail decides the outcome of each List attempt (attempt starts at 1).
	// Return errBlock to wait for the context.
	fail     func(kind, ns string, attempt int) error
	attempts map[string]int
	mu       chanMutex
}

type chanMutex chan struct{}

func newFakeCS(namespaces []string, fail func(kind, ns string, attempt int) error) *fakeCS {
	return &fakeCS{
		namespaces: namespaces,
		fail:       fail,
		attempts:   map[string]int{},
		mu:         make(chanMutex, 1),
	}
}

func (f *fakeCS) check(ctx context.Context, kind, ns string) error {
	f.mu <- struct{}{}
	key := kind + "/" + ns
	f.attempts[key]++
	n := f.attempts[key]
	<-f.mu
	if f.fail == nil {
		return nil
	}
	err := f.fail(kind, ns, n)
	if err == errBlock {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (f *fakeCS) CoreV1() corev1c.CoreV1Interface { return &fakeCore{f: f} }
func (f *fakeCS) AppsV1() appsv1c.AppsV1Interface { return &fakeApps{f: f} }
func (f *fakeCS) BatchV1() batchv1c.BatchV1Interface {
	return &fakeBatch{f: f}
}

type fakeCore struct {
	corev1c.CoreV1Interface
	f *fakeCS
}

func (c *fakeCore) Namespaces() corev1c.NamespaceInterface { return &fakeNamespaces{f: c.f} }
func (c *fakeCore) Pods(ns string) corev1c.PodInterface    { return &fakePods{f: c.f, ns: ns} }

type fakeApps struct {
	appsv1c.AppsV1Interface
	f *fakeCS
}

func (a *fakeApps) Deployments(ns string) appsv1c.DeploymentInterface {
	return &fakeDeployments{f: a.f, ns: ns}
}
func (a *fakeApps) DaemonSets(ns string) appsv1c.DaemonSetInterface {
	return &fakeDaemonSets{f: a.f, ns: ns}
}
func (a *fakeApps) StatefulSets(ns string) appsv1c.StatefulSetInterface {
	return &fakeStatefulSets{f: a.f, ns: ns}
}

type fakeBatch struct {
	batchv1c.BatchV1Interface
	f *fakeCS
}

func (b *fakeBatch) CronJobs(ns string) batchv1c.CronJobInterface {
	return &fakeCronJobs{f: b.f, ns: ns}
}
func (b *fakeBatch) Jobs(ns string) batchv1c.JobInterface { return &fakeJobs{f: b.f, ns: ns} }

type fakeNamespaces struct {
	corev1c.NamespaceInterface
	f *fakeCS
}

func (n *fakeNamespaces) List(ctx context.Context, _ metav1.ListOptions) (*corev1.NamespaceList, error) {
	if err := n.f.check(ctx, "namespaces", ""); err != nil {
		return nil, err
	}
	l := &corev1.NamespaceList{}
	for _, name := range n.f.namespaces {
		l.Items = append(l.Items, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	}
	return l, nil
}

type fakePods struct {
	corev1c.PodInterface
	f  *fakeCS
	ns string
}

func (p *fakePods) List(ctx context.Context, _ metav1.ListOptions) (*corev1.PodList, error) {
	if err := p.f.check(ctx, "pods", p.ns); err != nil {
		return nil, err
	}
	return &corev1.PodList{}, nil
}

type fakeDeployments struct {
	appsv1c.DeploymentInterface
	f  *fakeCS
	ns string
}

func (d *fakeDeployments) List(ctx context.Context, _ metav1.ListOptions) (*appsv1.DeploymentList, error) {
	if err := d.f.check(ctx, "deployments", d.ns); err != nil {
		return nil, err
	}
	dep := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: d.ns}}
	dep.Spec.Template.Spec.Containers = []corev1.Container{{Name: "app", Image: "example.lan/" + d.ns + "/app:1"}}
	return &appsv1.DeploymentList{Items: []appsv1.Deployment{dep}}, nil
}

type fakeDaemonSets struct {
	appsv1c.DaemonSetInterface
	f  *fakeCS
	ns string
}

func (d *fakeDaemonSets) List(ctx context.Context, _ metav1.ListOptions) (*appsv1.DaemonSetList, error) {
	if err := d.f.check(ctx, "daemonsets", d.ns); err != nil {
		return nil, err
	}
	return &appsv1.DaemonSetList{}, nil
}

type fakeStatefulSets struct {
	appsv1c.StatefulSetInterface
	f  *fakeCS
	ns string
}

func (s *fakeStatefulSets) List(ctx context.Context, _ metav1.ListOptions) (*appsv1.StatefulSetList, error) {
	if err := s.f.check(ctx, "statefulsets", s.ns); err != nil {
		return nil, err
	}
	return &appsv1.StatefulSetList{}, nil
}

type fakeCronJobs struct {
	batchv1c.CronJobInterface
	f  *fakeCS
	ns string
}

func (c *fakeCronJobs) List(ctx context.Context, _ metav1.ListOptions) (*batchv1.CronJobList, error) {
	if err := c.f.check(ctx, "cronjobs", c.ns); err != nil {
		return nil, err
	}
	l := &batchv1.CronJobList{}
	if c.ns == "ns-a" {
		cj := batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: c.ns}}
		cj.Spec.JobTemplate.Spec.Template.Spec.Containers = []corev1.Container{{Name: "job", Image: "example.lan/cron/job:1"}}
		l.Items = append(l.Items, cj)
	}
	return l, nil
}

type fakeJobs struct {
	batchv1c.JobInterface
	f  *fakeCS
	ns string
}

func (j *fakeJobs) List(ctx context.Context, _ metav1.ListOptions) (*batchv1.JobList, error) {
	if err := j.f.check(ctx, "jobs", j.ns); err != nil {
		return nil, err
	}
	return &batchv1.JobList{}, nil
}
