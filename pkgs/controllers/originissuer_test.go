package controllers

import (
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	"gotest.tools/v3/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	fakeClock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestOriginIssuerReconcile(t *testing.T) {
	assert.NilError(t, cmapi.AddToScheme(scheme.Scheme))
	assert.NilError(t, v1.AddToScheme(scheme.Scheme))

	clock := fakeClock.NewFakeClock(time.Now().Truncate(time.Second))
	now := metav1.NewTime(clock.Now())

	tests := []struct {
		name          string
		objects       []runtime.Object
		expected      v1.OriginIssuerStatus
		error         string
		namespaceName types.NamespacedName
	}{
		{
			name: "working serviceKeyRef",
			objects: []runtime.Object{
				&v1.OriginIssuer{
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
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-service-key",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"key": []byte("djEuMC0weDAwQkFCMTBD"),
					},
				},
			},
			expected: v1.OriginIssuerStatus{
				Conditions: []v1.OriginIssuerCondition{
					{
						Type:               v1.ConditionReady,
						Status:             v1.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Verified",
						Message:            "OriginIssuer verified and ready to sign certificates",
					},
				},
			},
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foo",
			},
		},
		{
			name: "missing serviceKeyRef",
			objects: []runtime.Object{
				&v1.OriginIssuer{
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
				},
			},
			expected: v1.OriginIssuerStatus{
				Conditions: []v1.OriginIssuerCondition{
					{
						Type:               v1.ConditionReady,
						Status:             v1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "NotFound",
						Message:            `Failed to retrieve auth secret: secrets "issuer-service-key" not found`,
					},
				},
			},
			error: `secrets "issuer-service-key" not found`,
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foo",
			},
		},
		{
			name: "serviceKeyRef missing key",
			objects: []runtime.Object{
				&v1.OriginIssuer{
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
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-service-key",
						Namespace: "default",
					},
					Data: map[string][]byte{},
				},
			},
			expected: v1.OriginIssuerStatus{
				Conditions: []v1.OriginIssuerCondition{
					{
						Type:               v1.ConditionReady,
						Status:             v1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "NotFound",
						Message:            `Failed to retrieve auth secret: secret issuer-service-key does not contain key "key"`,
					},
				},
			},
			error: `secret issuer-service-key does not contain key "key"`,
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foo",
			},
		},
		{
			name: "working tokenRef",
			objects: []runtime.Object{
				&v1.OriginIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "default",
					},
					Spec: v1.OriginIssuerSpec{
						RequestType: v1.RequestTypeOriginRSA,
						Auth: v1.OriginIssuerAuthentication{
							TokenRef: &v1.SecretKeySelector{
								Name: "issuer-api-token",
								Key:  "token",
							},
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-api-token",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"token": []byte("djEuMC0weDAwQkFCMTBD"),
					},
				},
			},
			expected: v1.OriginIssuerStatus{
				Conditions: []v1.OriginIssuerCondition{
					{
						Type:               v1.ConditionReady,
						Status:             v1.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Verified",
						Message:            "OriginIssuer verified and ready to sign certificates",
					},
				},
			},
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foo",
			},
		},
		{
			name: "unset authentication",
			objects: []runtime.Object{
				&v1.OriginIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "default",
					},
					Spec: v1.OriginIssuerSpec{
						RequestType: v1.RequestTypeOriginRSA,
					},
				},
			},
			expected: v1.OriginIssuerStatus{
				Conditions: []v1.OriginIssuerCondition{
					{
						Type:               v1.ConditionReady,
						Status:             v1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "MissingAuthentication",
						Message:            "No authentication methods were configured",
					},
				},
			},
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithRuntimeObjects(tt.objects...).
				WithStatusSubresource(&v1.OriginIssuer{}).
				Build()

			controller := &OriginIssuerController{
				Client: client,
				Reader: client,
				Clock:  clock,
				Log:    logf.Log,
			}

			_, err := reconcile.AsReconciler(client, controller).Reconcile(t.Context(), reconcile.Request{
				NamespacedName: tt.namespaceName,
			})
			if tt.error == "" {
				assert.NilError(t, err)
			} else {
				assert.Error(t, err, tt.error)
			}

			got := &v1.OriginIssuer{}
			assert.NilError(t, client.Get(t.Context(), tt.namespaceName, got))
			assert.DeepEqual(t, got.Status, tt.expected)
		})
	}
}
