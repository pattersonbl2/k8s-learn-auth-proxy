package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	appsv1 "k8s.io/api/apps/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"golang.org/x/crypto/bcrypt"
)

type ProvisionResult struct {
	Namespace string
	Password  string
	Token     string
	LoginURL  string
}

type Provisioner struct {
	client kubernetes.Interface
	n8nURL string
}

func (p *Provisioner) Provision(ctx context.Context, name, email string) (*ProvisionResult, error) {
	nsName := "learn-" + name
	password := generateRandomString(16)
	token := generateRandomHex(32)

	// 1. Create namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"managed-by":                           "k8s-learn",
				"pod-security.kubernetes.io/enforce":    "baseline",
				"created-at":                            time.Now().UTC().Format("20060102T150405Z"),
			},
		},
	}
	if _, err := p.client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
	}

	// 2. Create RBAC
	if err := p.createRBAC(ctx, nsName); err != nil {
		return nil, fmt.Errorf("create RBAC: %w", err)
	}

	// 3. Create resource limits
	if err := p.createResourceLimits(ctx, nsName); err != nil {
		return nil, fmt.Errorf("create resource limits: %w", err)
	}

	// 4. Create auth secret
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt hash: %w", err)
	}
	if err := p.createAuthSecret(ctx, nsName, string(hashBytes), token); err != nil {
		return nil, fmt.Errorf("create auth secret: %w", err)
	}

	// 5. Deploy ttyd + auth-proxy sidecar
	if err := p.createDeployment(ctx, nsName, name); err != nil {
		return nil, fmt.Errorf("create deployment: %w", err)
	}
	if err := p.createService(ctx, nsName); err != nil {
		return nil, fmt.Errorf("create service: %w", err)
	}
	if err := p.createIngress(ctx, nsName, name); err != nil {
		return nil, fmt.Errorf("create ingress: %w", err)
	}

	// 6. Wait for deployment ready
	if err := p.waitForReady(ctx, nsName); err != nil {
		return nil, fmt.Errorf("deployment not ready: %w", err)
	}

	loginURL := fmt.Sprintf("https://learn-%s.bp31app.com?token=%s", name, token)

	// 7. Fire notification (async, don't block)
	go p.sendNotification(name, email, loginURL, password)

	return &ProvisionResult{
		Namespace: nsName,
		Password:  password,
		Token:     token,
		LoginURL:  loginURL,
	}, nil
}

func (p *Provisioner) createRBAC(ctx context.Context, nsName string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "user-sa", Namespace: nsName},
	}
	if _, err := p.client.CoreV1().ServiceAccounts(nsName).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
		return err
	}

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "user-role", Namespace: nsName},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "services", "configmaps", "secrets"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
			{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		},
	}
	if _, err := p.client.RbacV1().Roles(nsName).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		return err
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "user-binding", Namespace: nsName},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "user-sa", Namespace: nsName}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "user-role"},
	}
	if _, err := p.client.RbacV1().RoleBindings(nsName).Create(ctx, rb, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func (p *Provisioner) createResourceLimits(ctx context.Context, nsName string) error {
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "default-limits", Namespace: nsName},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				Default: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
				DefaultRequest: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			}},
		},
	}
	if _, err := p.client.CoreV1().LimitRanges(nsName).Create(ctx, lr, metav1.CreateOptions{}); err != nil {
		return err
	}

	rq := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "user-quota", Namespace: nsName},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourcePods:            resource.MustParse("10"),
				corev1.ResourceRequestsCPU:     resource.MustParse("1"),
				corev1.ResourceRequestsMemory:  resource.MustParse("1Gi"),
			},
		},
	}
	if _, err := p.client.CoreV1().ResourceQuotas(nsName).Create(ctx, rq, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func (p *Provisioner) createAuthSecret(ctx context.Context, nsName, passHash, token string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ttyd-auth", Namespace: nsName},
		StringData: map[string]string{
			"TERM_PASS_HASH": passHash,
			"SIGNUP_TOKEN":   token,
		},
	}
	_, err := p.client.CoreV1().Secrets(nsName).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

func (p *Provisioner) createDeployment(ctx context.Context, nsName, userName string) error {
	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "ttyd", Namespace: nsName},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ttyd"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "ttyd"}},
				Spec: corev1.PodSpec{
					ServiceAccountName: "user-sa",
					InitContainers: []corev1.Container{{
						Name:    "install-kubectl",
						Image:   "bitnami/kubectl:latest",
						Command: []string{"cp", "/opt/bitnami/kubectl/bin/kubectl", "/shared/kubectl"},
						VolumeMounts: []corev1.VolumeMount{{Name: "shared", MountPath: "/shared"}},
					}, {
						Name:    "hash-password",
						Image:   "ghcr.io/pattersonbl2/k8s-learn-auth-proxy:latest",
						Args:    []string{"--hash"},
						Env: []corev1.EnvVar{{
							Name: "TERM_PASS", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "ttyd-auth"},
									Key:                  "TERM_PASS_HASH",
								},
							},
						}},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "auth", MountPath: "/auth"},
							{Name: "auth-secret", MountPath: "/auth-secret"},
						},
					}},
					Containers: []corev1.Container{{
						Name:    "ttyd",
						Image:   "tsl0922/ttyd:latest",
						Args:    []string{"--port", "7681", "--writable", "/shared/kubectl", "exec", "-it", "bash"},
						Ports:   []corev1.ContainerPort{{ContainerPort: 7681}},
						VolumeMounts: []corev1.VolumeMount{{Name: "shared", MountPath: "/shared"}},
					}, {
						Name:  "auth-proxy",
						Image: "ghcr.io/pattersonbl2/k8s-learn-auth-proxy:latest",
						Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
						VolumeMounts: []corev1.VolumeMount{{Name: "auth", MountPath: "/auth"}},
					}},
					Volumes: []corev1.Volume{
						{Name: "shared", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{Name: "auth", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{Name: "auth-secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "ttyd-auth"}}},
					},
				},
			},
		},
	}
	_, err := p.client.AppsV1().Deployments(nsName).Create(ctx, dep, metav1.CreateOptions{})
	return err
}

func (p *Provisioner) createService(ctx context.Context, nsName string) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "ttyd", Namespace: nsName},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "ttyd"},
			Ports:    []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}},
		},
	}
	_, err := p.client.CoreV1().Services(nsName).Create(ctx, svc, metav1.CreateOptions{})
	return err
}

func (p *Provisioner) createIngress(ctx context.Context, nsName, userName string) error {
	pathType := netv1.PathTypePrefix
	className := "traefik"
	ing := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ttyd",
			Namespace: nsName,
			Annotations: map[string]string{
				"traefik.ingress.kubernetes.io/router.entrypoints": "web",
			},
		},
		Spec: netv1.IngressSpec{
			IngressClassName: &className,
			Rules: []netv1.IngressRule{{
				Host: fmt.Sprintf("learn-%s.bp31app.com", userName),
				IngressRuleValue: netv1.IngressRuleValue{
					HTTP: &netv1.HTTPIngressRuleValue{
						Paths: []netv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathType,
							Backend: netv1.IngressBackend{
								Service: &netv1.IngressServiceBackend{
									Name: "ttyd",
									Port: netv1.ServiceBackendPort{Number: 8080},
								},
							},
						}},
					},
				},
			}},
		},
	}
	_, err := p.client.NetworkingV1().Ingresses(nsName).Create(ctx, ing, metav1.CreateOptions{})
	return err
}

func (p *Provisioner) waitForReady(ctx context.Context, nsName string) error {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	return wait.PollUntilContextCancel(ctx, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		dep, err := p.client.AppsV1().Deployments(nsName).Get(ctx, "ttyd", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return dep.Status.ReadyReplicas >= 1, nil
	})
}

func (p *Provisioner) sendNotification(username, email, loginURL, password string) {
	body := fmt.Sprintf(`{"username":%q,"email":%q,"loginUrl":%q,"password":%q}`, username, email, loginURL, password)
	resp, err := http.Post(p.n8nURL, "application/json", strings.NewReader(body))
	if err != nil {
		log.Printf("notification webhook failed: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("notification sent for %s", username)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func generateRandomHex(length int) string {
	b := make([]byte, length/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}
