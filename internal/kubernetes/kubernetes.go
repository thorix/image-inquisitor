package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultCallTimeout = 60 * time.Second
	defaultRetries     = 2
	defaultBackoff     = time.Second

	// listKindsPerNamespace is the number of resource kinds listed per namespace
	listKindsPerNamespace = 6
)

// ErrAllListsFailed is returned when every namespace x kind List call failed.
var ErrAllListsFailed = errors.New("every namespace List call failed")

type Kubernetes struct {
	*KubernetesConfig
	clientset kubernetes.Interface

	// CallTimeout is the deadline for each List attempt
	CallTimeout time.Duration
	// Retries is the number of retries after the first attempt
	Retries int
	// Backoff is the delay before the first retry; it doubles each retry
	Backoff time.Duration
}

type KubernetesConfig struct {
	IncludeNamespaces []string
	ExcludeNamespaces []string
}

// ListStats records List failures per namespace attempted.
type ListStats struct {
	// Namespaces holds every namespace attempted
	Namespaces []string
	// FailedLists maps every namespace attempted to the number of resource
	// kinds whose List still failed after retries (zeros included)
	FailedLists map[string]int
}

// Total returns the number of failed List calls across all namespaces.
func (s *ListStats) Total() int {
	if s == nil {
		return 0
	}
	total := 0
	for _, n := range s.FailedLists {
		total += n
	}
	return total
}

func NewKubernetes(c *KubernetesConfig) (*Kubernetes, error) {

	kubeRestConfig, err := rest.InClusterConfig()
	if err != nil {
		kubeRestConfig, err = clientcmd.BuildConfigFromFlags(
			"",
			clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename(),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to find kube config: %v", err)
		}
	}

	// Create a Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(kubeRestConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %s", err.Error())
	}

	return NewKubernetesWithClient(c, clientset), nil
}

// NewKubernetesWithClient builds a Kubernetes source around an existing client.
func NewKubernetesWithClient(c *KubernetesConfig, cs kubernetes.Interface) *Kubernetes {
	return &Kubernetes{
		KubernetesConfig: c,
		clientset:        cs,
		CallTimeout:      defaultCallTimeout,
		Retries:          defaultRetries,
		Backoff:          defaultBackoff,
	}
}

// listWithRetry runs one List call with a per-attempt deadline and retries.
// Forbidden and NotFound errors are never retried.
func listWithRetry[T any](ctx context.Context, k *Kubernetes, kind, ns string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	backoff := k.Backoff
	var err error
	for attempt := 0; attempt <= k.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		callCtx, cancel := context.WithTimeout(ctx, k.CallTimeout)
		var res T
		res, err = fn(callCtx)
		cancel()
		if err == nil {
			return res, nil
		}
		if apierrors.IsForbidden(err) || apierrors.IsNotFound(err) || ctx.Err() != nil {
			break
		}
		log.WithFields(log.Fields{"namespace": ns, "kind": kind, "phase": "list", "attempt": attempt + 1}).
			Debugf("list attempt failed: %v", err)
	}
	return zero, err
}

func (k *Kubernetes) included(name string) bool {
	if len(k.IncludeNamespaces) > 0 {
		found := false
		for _, n := range k.IncludeNamespaces {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, n := range k.ExcludeNamespaces {
		if n == name {
			return false
		}
	}
	return true
}

// GetReport retrieves all container images used by resources in all namespaces.
// A namespace List failure is an error. Per-namespace, per-kind List failures
// are tolerated and counted in ListStats, unless every one of them failed.
func (k *Kubernetes) GetReport(ctx context.Context) (KubernetesReport, *ListStats, error) {
	report := newKubernetesReportWrapper()

	namespaces, err := listWithRetry(ctx, k, "namespaces", "", func(c context.Context) (*corev1.NamespaceList, error) {
		return k.clientset.CoreV1().Namespaces().List(c, v1.ListOptions{})
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing namespaces: %w", err)
	}

	stats := &ListStats{FailedLists: make(map[string]int)}
	var statsMu sync.Mutex
	fail := func(ns, kind string, err error) {
		log.WithFields(log.Fields{"namespace": ns, "kind": kind, "phase": "list"}).
			Errorf("list failed: %v", err)
		statsMu.Lock()
		stats.FailedLists[ns]++
		statsMu.Unlock()
	}

	wg := sync.WaitGroup{}
	for _, nsItem := range namespaces.Items {
		if !k.included(nsItem.Name) {
			continue
		}
		stats.Namespaces = append(stats.Namespaces, nsItem.Name)
		stats.FailedLists[nsItem.Name] = 0

		wg.Add(1)
		go func(namespace string) {
			defer wg.Done()
			log.Debugf("scanning Kubernetes namespace: %s", namespace)

			if pods, err := listWithRetry(ctx, k, "pods", namespace, func(c context.Context) (*corev1.PodList, error) {
				return k.clientset.CoreV1().Pods(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "pods", err)
			} else {
				for _, pod := range pods.Items {
					// Only capture pods not owned by a regular resource
					owned := false
					for _, owner := range pod.GetObjectMeta().GetOwnerReferences() {
						if owner.Kind == "ReplicaSet" || owner.Kind == "StatefulSet" ||
							owner.Kind == "DaemonSet" || owner.Kind == "Job" {
							owned = true
							break
						}
					}
					if owned {
						continue
					}
					for _, c := range pod.Spec.InitContainers {
						report.Add(c.Image, "Pod", c.Name, true, &pod)
					}
					for _, c := range pod.Spec.Containers {
						report.Add(c.Image, "Pod", c.Name, false, &pod)
					}
				}
			}

			if deps, err := listWithRetry(ctx, k, "deployments", namespace, func(c context.Context) (*appsv1.DeploymentList, error) {
				return k.clientset.AppsV1().Deployments(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "deployments", err)
			} else {
				for _, d := range deps.Items {
					for _, c := range d.Spec.Template.Spec.InitContainers {
						report.Add(c.Image, "Deployment", c.Name, true, &d)
					}
					for _, c := range d.Spec.Template.Spec.Containers {
						report.Add(c.Image, "Deployment", c.Name, false, &d)
					}
				}
			}

			if dss, err := listWithRetry(ctx, k, "daemonsets", namespace, func(c context.Context) (*appsv1.DaemonSetList, error) {
				return k.clientset.AppsV1().DaemonSets(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "daemonsets", err)
			} else {
				for _, d := range dss.Items {
					for _, c := range d.Spec.Template.Spec.InitContainers {
						report.Add(c.Image, "DaemonSet", c.Name, true, &d)
					}
					for _, c := range d.Spec.Template.Spec.Containers {
						report.Add(c.Image, "DaemonSet", c.Name, false, &d)
					}
				}
			}

			if sss, err := listWithRetry(ctx, k, "statefulsets", namespace, func(c context.Context) (*appsv1.StatefulSetList, error) {
				return k.clientset.AppsV1().StatefulSets(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "statefulsets", err)
			} else {
				for _, s := range sss.Items {
					for _, c := range s.Spec.Template.Spec.InitContainers {
						report.Add(c.Image, "StatefulSet", c.Name, true, &s)
					}
					for _, c := range s.Spec.Template.Spec.Containers {
						report.Add(c.Image, "StatefulSet", c.Name, false, &s)
					}
				}
			}

			if cjs, err := listWithRetry(ctx, k, "cronjobs", namespace, func(c context.Context) (*batchv1.CronJobList, error) {
				return k.clientset.BatchV1().CronJobs(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "cronjobs", err)
			} else {
				for _, cj := range cjs.Items {
					for _, c := range cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers {
						report.Add(c.Image, "CronJob", c.Name, true, &cj)
					}
					for _, c := range cj.Spec.JobTemplate.Spec.Template.Spec.Containers {
						report.Add(c.Image, "CronJob", c.Name, false, &cj)
					}
				}
			}

			if jobs, err := listWithRetry(ctx, k, "jobs", namespace, func(c context.Context) (*batchv1.JobList, error) {
				return k.clientset.BatchV1().Jobs(namespace).List(c, v1.ListOptions{})
			}); err != nil {
				fail(namespace, "jobs", err)
			} else {
				for _, job := range jobs.Items {
					// Only capture jobs not owned by a CronJob
					owned := false
					for _, owner := range job.GetObjectMeta().GetOwnerReferences() {
						if owner.Kind == "CronJob" {
							owned = true
							break
						}
					}
					if owned {
						continue
					}
					for _, c := range job.Spec.Template.Spec.InitContainers {
						report.Add(c.Image, "Job", c.Name, true, &job)
					}
					for _, c := range job.Spec.Template.Spec.Containers {
						report.Add(c.Image, "Job", c.Name, false, &job)
					}
				}
			}

			log.Debugf("DONE scanning Kubernetes namespace: %s", namespace)
		}(nsItem.Name)
	}

	wg.Wait()

	if n := len(stats.Namespaces); n > 0 && stats.Total() == n*listKindsPerNamespace {
		return report.GetReport(), stats, fmt.Errorf("%w (%d lists)", ErrAllListsFailed, stats.Total())
	}

	return report.GetReport(), stats, nil
}
