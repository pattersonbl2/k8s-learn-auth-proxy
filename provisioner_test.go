package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/kubernetes/fake"
	"golang.org/x/crypto/bcrypt"
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
	if _, ok := secret.StringData["TERM_PASS"]; !ok {
		t.Error("secret missing TERM_PASS")
	}
	if _, ok := secret.StringData["SIGNUP_TOKEN"]; !ok {
		t.Error("secret missing SIGNUP_TOKEN")
	}
}

// findInitContainer returns the named init container from a deployment spec, or nil.
func findInitContainer(dep *appsv1.Deployment, name string) *corev1.Container {
	for i := range dep.Spec.Template.Spec.InitContainers {
		if dep.Spec.Template.Spec.InitContainers[i].Name == name {
			return &dep.Spec.Template.Spec.InitContainers[i]
		}
	}
	return nil
}

// TestProvisionedPasswordValidatesAfterHashing reproduces the reported login
// bug end-to-end: it reads the exact secret value the deployment wires into
// the hash-password init container's TERM_PASS env var, runs it through the
// real runHashMode (the init container's actual code), and checks the
// resulting hash validates against the plaintext password that gets emailed
// to the user. If the secret already holds a bcrypt hash, runHashMode hashes
// it a second time and this must fail.
func TestProvisionedPasswordValidatesAfterHashing(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	result, err := p.Provision(context.Background(), "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	dep, err := client.AppsV1().Deployments("learn-testuser").Get(context.Background(), "ttyd", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}
	hashInit := findInitContainer(dep, "hash-password")
	if hashInit == nil {
		t.Fatal("hash-password init container not found")
	}

	var secretKey string
	for _, e := range hashInit.Env {
		if e.Name == "TERM_PASS" && e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			secretKey = e.ValueFrom.SecretKeyRef.Key
		}
	}
	if secretKey == "" {
		t.Fatal("hash-password init container has no TERM_PASS env var backed by a SecretKeyRef")
	}

	secret, err := client.CoreV1().Secrets("learn-testuser").Get(context.Background(), "ttyd-auth", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Secret not created: %v", err)
	}
	secretVal, ok := secret.StringData[secretKey]
	if !ok {
		t.Fatalf("secret missing key %q referenced by TERM_PASS env var", secretKey)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "password-hash")
	t.Setenv("TERM_PASS", secretVal)
	if err := runHashMode(outPath); err != nil {
		t.Fatalf("runHashMode failed: %v", err)
	}

	hashBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading hash output: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword(hashBytes, []byte(result.Password)); err != nil {
		t.Fatalf("emailed password %q does not validate against the deployed password hash: %v", result.Password, err)
	}
}

// TestHashPasswordInitContainerTokenPathMatchesSecretKey reproduces a second
// login bug: the Secret volume mounts each StringData key as a file of the
// same name (the token is stored under key SIGNUP_TOKEN, see
// createAuthSecret), but the init container must be explicitly told that
// filename via AUTH_SECRET_TOKEN_PATH, or main.go's default
// ("/auth-secret/token") never matches and the token copy silently no-ops —
// breaking the one-time login link for every user.
func TestHashPasswordInitContainerTokenPathMatchesSecretKey(t *testing.T) {
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
	hashInit := findInitContainer(dep, "hash-password")
	if hashInit == nil {
		t.Fatal("hash-password init container not found")
	}

	var tokenPathEnv string
	for _, e := range hashInit.Env {
		if e.Name == "AUTH_SECRET_TOKEN_PATH" {
			tokenPathEnv = e.Value
		}
	}

	const wantSuffix = "/SIGNUP_TOKEN"
	if !strings.HasSuffix(tokenPathEnv, wantSuffix) {
		t.Fatalf("hash-password init container AUTH_SECRET_TOKEN_PATH = %q, want a path ending in %q to match the secret's actual SIGNUP_TOKEN key", tokenPathEnv, wantSuffix)
	}
}

// TestCreateResourceLimitsQuotaSizedForConcurrentLearners checks the
// per-learner ResourceQuota is tight enough that 40 concurrent learners
// can't exceed the homelab's real capacity, while still leaving room for a
// learner to spin up a couple of their own test pods.
func TestCreateResourceLimitsQuotaSizedForConcurrentLearners(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	if err := p.createResourceLimits(context.Background(), "learn-testuser"); err != nil {
		t.Fatalf("createResourceLimits failed: %v", err)
	}

	rq, err := client.CoreV1().ResourceQuotas("learn-testuser").Get(context.Background(), "user-quota", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ResourceQuota not created: %v", err)
	}

	wantCPU := resource.MustParse("300m")
	wantMem := resource.MustParse("384Mi")
	wantPods := resource.MustParse("6")

	if got := rq.Spec.Hard[corev1.ResourceRequestsCPU]; got.Cmp(wantCPU) != 0 {
		t.Errorf("requests.cpu = %s, want %s", got.String(), wantCPU.String())
	}
	if got := rq.Spec.Hard[corev1.ResourceRequestsMemory]; got.Cmp(wantMem) != 0 {
		t.Errorf("requests.memory = %s, want %s", got.String(), wantMem.String())
	}
	if got := rq.Spec.Hard[corev1.ResourcePods]; got.Cmp(wantPods) != 0 {
		t.Errorf("pods = %s, want %s", got.String(), wantPods.String())
	}
}

// TestProvisionRejectsWhenAtCapacity reproduces the "unbounded signups" gap:
// nothing today stops more than N concurrent learners from being
// provisioned, which combined with per-namespace quota could exceed
// available homelab capacity.
func TestProvisionRejectsWhenAtCapacity(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification", maxActiveLearners: 2}

	for i := 0; i < 2; i++ {
		if _, err := p.Provision(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i)); err != nil {
			t.Fatalf("Provision %d failed: %v", i, err)
		}
	}

	if _, err := p.Provision(context.Background(), "onemore", "onemore@example.com"); err == nil {
		t.Fatal("expected Provision to fail once at capacity")
	}

	if _, err := client.CoreV1().Namespaces().Get(context.Background(), "learn-onemore", metav1.GetOptions{}); err == nil {
		t.Error("namespace should not have been created when at capacity")
	}
}

// TestProvisionUnlimitedWhenCapacityUnset preserves the zero-value default:
// existing tests and callers that don't set maxActiveLearners must keep
// working with no cap enforced.
func TestProvisionUnlimitedWhenCapacityUnset(t *testing.T) {
	client := fakeReadyClient()
	p := &Provisioner{client: client, n8nURL: "http://localhost:9999/webhook/k8s-learn-notification"}

	for i := 0; i < 5; i++ {
		if _, err := p.Provision(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i)); err != nil {
			t.Fatalf("Provision %d failed: %v", i, err)
		}
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
