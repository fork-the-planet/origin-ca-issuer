package controllers

import (
	"os"
	"path/filepath"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/poll"
	"gotest.tools/v3/skip"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestOriginIssuerReconcileSuite(t *testing.T) {
	issuer := &v1.OriginIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: v1.OriginIssuerSpec{
			RequestType: v1.RequestTypeOriginRSA,
			Auth: v1.OriginIssuerAuthentication{
				ServiceKeyRef: &v1.SecretKeySelector{
					Name: "issuer-service-key",
					Key:  "key",
				},
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "issuer-service-key",
			Namespace: "default",
		},
		StringData: map[string]string{
			"key": "v1.0-0x00BAB10C",
		},
	}

	skip.If(t, os.Getenv("KUBEBUILDER_ASSETS") == "", "no kubebuilder environment")

	cfg, err := envtestConfig(t)
	assert.NilError(t, err)

	mgr, err := manager.New(cfg, manager.Options{
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		Scheme: scheme.Scheme,
	})
	assert.NilError(t, err)
	c := mgr.GetClient()

	controller := &OriginIssuerController{
		Client: c,
		Reader: c,
		Clock:  clock.RealClock{},
		Log:    logf.Log,
	}

	builder.ControllerManagedBy(mgr).
		For(&v1.OriginIssuer{}).
		Complete(reconcile.AsReconciler(c, controller))

	StartTestManager(mgr, t)

	ctx := t.Context()

	assert.NilError(t, c.Create(ctx, secret))
	defer c.Delete(ctx, secret)

	assert.NilError(t, c.Create(ctx, issuer))
	defer c.Delete(ctx, issuer)

	poll.WaitOn(t, func(t poll.LogT) poll.Result {
		iss := v1.OriginIssuer{}
		namespacedName := types.NamespacedName{
			Namespace: issuer.Namespace,
			Name:      issuer.Name,
		}
		err := c.Get(ctx, namespacedName, &iss)
		if err != nil {
			return poll.Continue("issuer %q was not created", namespacedName.String())
		}

		if IssuerStatusHasCondition(iss.Status, v1.OriginIssuerCondition{Type: v1.ConditionReady, Status: v1.ConditionTrue}) {
			return poll.Success()
		}

		return poll.Continue("issuer %q did not have ready condition", namespacedName.String())
	})
}

func envtestConfig(t *testing.T) (*rest.Config, error) {
	t.Helper()

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")},
	}
	cmapi.AddToScheme(scheme.Scheme)
	v1.AddToScheme(scheme.Scheme)

	cfg, err := env.Start()
	assert.NilError(t, err)

	t.Cleanup(func() {
		assert.NilError(t, env.Stop())
	})

	return cfg, nil
}

func StartTestManager(mgr manager.Manager, t *testing.T) {
	t.Helper()

	var err error
	go func() {
		err = mgr.Start(t.Context())
	}()

	t.Cleanup(func() {
		assert.NilError(t, err)
	})
}
