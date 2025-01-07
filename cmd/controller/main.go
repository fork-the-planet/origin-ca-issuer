package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cloudflare/origin-ca-issuer/cmd/controller/options"
	"github.com/cloudflare/origin-ca-issuer/internal/cfapi"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	"github.com/cloudflare/origin-ca-issuer/pkgs/controllers"
	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

func main() {
	fs := pflag.CommandLine
	o := options.NewControllerOptions()
	o.AddFlags(fs)

	_ = fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	crlog.SetLogger(logr.FromSlogHandler(logger.Handler()))

	if err := o.Validate(); err != nil {
		logger.Error("error validating options", "error", err)
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		logger.Error("could not add to scheme", "error", err)
		os.Exit(1)
	}
	if err := certmanager.AddToScheme(scheme); err != nil {
		logger.Error("could not add to scheme", "error", err)
		os.Exit(1)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		logger.Error("could not add to scheme", "error", err)
		os.Exit(1)
	}

	kubeCfg, err := config.GetConfig()
	if err != nil {
		logger.Error("could not load kubeconfig", "error", err)
		os.Exit(1)
	}

	kubeCfg.QPS = o.KubernetesAPIQPS
	kubeCfg.Burst = o.KubernetesAPIBurst

	mgr, err := manager.New(kubeCfg, manager.Options{
		Scheme: scheme,
	})
	if err != nil {
		logger.Error("could not create manager", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(signals.SetupSignalHandler())
	defer cancel()

	signer := &controllers.Signer{
		Reader:                   mgr.GetAPIReader(),
		ClusterResourceNamespace: o.ClusterResourceNamespace,
		Builder: cfapi.NewBuilder().WithClient(&http.Client{
			Timeout: 30 * time.Second,
		}),
	}
	signer.SetupWithManager(ctx, mgr)

	if err := mgr.Start(ctx); err != nil {
		logger.Error("could not start manager", "error", err)
		os.Exit(1)
	}
}
