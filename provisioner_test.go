package main

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeReadyClient returns a fake clientset where any deployment Get
// also reports ReadyReplicas=1, so waitForReady returns immediately.
func fakeReadyClient() *fake.Clientset {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "deployments", func(action clienttesting.Action) (bool, runtime.Object, error) {
		getAction := action.(clienttesting.GetAction)
		dep, err := client.Tracker().Get(
			appsv1.SchemeGroupVersion.WithResource("deployments"),
			getAction.GetNamespace(),
			getAction.GetName(),
		)
		if err != nil {
			return true, nil, err
		}
		d := dep.(*appsv1.Deployment)
		d.Status.ReadyReplicas = 1
		return true, d, nil
	})
	return client
}

func TestProvisionCreatesNamespace(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{
		client: client,
		n8nURL: "http://localhost:9999/webhook/k8s-learn-notification",
	}

	result, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ns, err := client.CoreV1().Namespaces().Get(context.Background(), "learn-testuser", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("namespace not created: %v", err)
	}

	if ns.Labels["managed-by"] != "k8s-learn" {
		t.Errorf("expected managed-by label, got %v", ns.Labels)
	}
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "baseline" {
		t.Errorf("expected pod security label")
	}
	if result.Namespace != "learn-testuser" {
		t.Errorf("expected namespace learn-testuser, got %s", result.Namespace)
	}
	if result.Password == "" || len(result.Password) != 16 {
		t.Errorf("expected 16-char password, got %q", result.Password)
	}
	if result.Token == "" || len(result.Token) != 32 {
		t.Errorf("expected 32-char token, got %q", result.Token)
	}
}

func TestProvisionCreatesRBAC(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	_, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ns := "learn-testuser"
	if _, err := client.CoreV1().ServiceAccounts(ns).Get(context.Background(), "user-sa", metav1.GetOptions{}); err != nil {
		t.Fatalf("ServiceAccount not created: %v", err)
	}
	if _, err := client.RbacV1().Roles(ns).Get(context.Background(), "user-role", metav1.GetOptions{}); err != nil {
		t.Fatalf("Role not created: %v", err)
	}
	if _, err := client.RbacV1().RoleBindings(ns).Get(context.Background(), "user-binding", metav1.GetOptions{}); err != nil {
		t.Fatalf("RoleBinding not created: %v", err)
	}
}

func TestProvisionCreatesDeployment(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	_, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	dep, err := client.AppsV1().Deployments("learn-testuser").Get(context.Background(), "ttyd", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}
	if len(dep.Spec.Template.Spec.Containers) != 2 {
		t.Errorf("expected 2 containers (ttyd + auth-proxy), got %d", len(dep.Spec.Template.Spec.Containers))
	}
	if len(dep.Spec.Template.Spec.InitContainers) != 2 {
		t.Errorf("expected 2 init containers (kubectl + hash), got %d", len(dep.Spec.Template.Spec.InitContainers))
	}
}

func TestProvisionCreatesIngress(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	_, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	ing, err := client.NetworkingV1().Ingresses("learn-testuser").Get(context.Background(), "ttyd", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Ingress not created: %v", err)
	}
	if ing.Spec.Rules[0].Host != "learn-testuser.bp31app.com" {
		t.Errorf("expected host learn-testuser.bp31app.com, got %s", ing.Spec.Rules[0].Host)
	}
}

func TestProvisionCreatesAuthSecret(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	_, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	secret, err := client.CoreV1().Secrets("learn-testuser").Get(context.Background(), "ttyd-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Secret not created: %v", err)
	}
	if _, ok := secret.StringData["TERM_PASS_HASH"]; !ok {
		t.Error("secret missing TERM_PASS_HASH")
	}
	if _, ok := secret.StringData["SIGNUP_TOKEN"]; !ok {
		t.Error("secret missing SIGNUP_TOKEN")
	}
}

func TestProvisionDuplicateNameFails(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	_, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("first Provision failed: %v", err)
	}

	_, err = p.Provision(context.Background(), "testuser", "test2@example.com")
	if err == nil {
		t.Fatal("second Provision with same name should fail")
	}
}

func TestProvisionReturnsLoginURL(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	result, err := p.Provision(context.Background(), "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if !strings.HasPrefix(result.LoginURL, "https://learn-alice.bp31app.com?token=") {
		t.Errorf("unexpected login URL: %s", result.LoginURL)
	}
}
