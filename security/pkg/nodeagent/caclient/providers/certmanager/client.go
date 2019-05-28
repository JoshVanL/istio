// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	certmanagerclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	caClientInterface "istio.io/istio/security/pkg/nodeagent/caclient/interface"
	"istio.io/pkg/log"
)

const (
	issuerName = "istio-cert-manager"
)

type certManagerClient struct {
	namespace   string
	enableTLS   bool
	tlsRootCert []byte

	restConfig *restclient.Config
	kClient    *kubeclient.Clientset
	cmClient   *certmanagerclient.Clientset

	mu sync.Mutex
}

// NewCertManagerClient create a CA client for Cert-Manager
func NewCertManagerClient(namespace string, tls bool, tlsRootCert []byte) (caClientInterface.Client, error) {
	log.Info("cert-manager: using cert-manager csr provider")
	c := &certManagerClient{
		namespace:   namespace,
		enableTLS:   tls,
		tlsRootCert: tlsRootCert,
	}

	restConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}

	if !tls {
		restConfig.Insecure = true
	} else {
		restConfig.Insecure = false
	}
	c.restConfig = restConfig

	c.kClient, err = kubeclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	c.cmClient, err = certmanagerclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	log.Info("cert-manager: csr provider ready")

	return c, nil
}

func (c *certManagerClient) CSRSign(ctx context.Context, csrPEM, keyPEM []byte, saToken string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	log.Info("cert-manager: csrSign called")

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("certificate signing request is not properly encoded")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert-manager: failed to parse certificate request: %s\n%s", err, csrPEM)
	}

	var uriNames []string
	for _, u := range csr.URIs {
		uriNames = append(csr.DNSNames, u.String())
	}

	if len(uriNames) == 0 {
		return nil, fmt.Errorf("no uri names in CSR")
	}

	name := fmt.Sprintf("%s",
		strings.ReplaceAll(strings.ReplaceAll(
			uriNames[0], "spiffe://", ""), "/", "-"))

	if err := c.ensureSecret(name, keyPEM); err != nil {
		return nil, err
	}

LOOP:
	for {

		select {
		case <-ctx.Done():
			log.Errorf("ctx error: %s", ctx.Err())
			return nil, ctx.Err()
		default:
		}

		cert, err := c.ensureCertificate(name, certValidTTLInSec, uriNames, csr)
		if err != nil {
			return nil, err
		}

		log.Infof("Certificate conditions: %s %s/%s", cert.Status.Conditions, c.namespace, name)

		for _, c := range cert.Status.Conditions {
			if c.Type != certmanagerv1.CertificateConditionReady {
				time.Sleep(time.Second * 2)
				continue LOOP
			}
		}

		log.Infof("Certificate conditions Ready %s %s/%s", cert.Status.Conditions, c.namespace, name)

		break
	}

	var tlsCert []byte
	var i int

	for {
		i++

		select {
		case <-ctx.Done():
			log.Errorf("ctx error: %s", ctx.Err())
			return nil, ctx.Err()
		default:
		}

		if i > 3 {
			return nil, fmt.Errorf(
				"failed to wait for certificate to become ready in secret %s/%s",
				c.namespace, name)
		}

		time.Sleep(time.Second * 2)

		log.Infof("waiting for certificate to become ready %s/%s ...", c.namespace, name)

		s, err := c.kClient.CoreV1().Secrets(c.namespace).Get(name+"-tls", metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				return nil, err
			}

			continue
		}

		cert, ok := s.Data[corev1.TLSCertKey]
		if ok && len(cert) > 0 {
			tlsCert = cert
			break
		}
	}

	var certChain []string
	var p *pem.Block
	for {
		p, tlsCert = pem.Decode(tlsCert)
		if p == nil {
			break
		}

		certChain = append([]string{string(pem.EncodeToMemory(p))}, certChain...)
	}

	ca, err := c.getCA()
	if err != nil {
		return nil, err
	}

	certChain = append(certChain, string(ca))

	err = c.cmClient.Certmanager().Certificates(c.namespace).Delete(name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to delete certificate %s: %s", name, err)
	}

	err = c.kClient.Core().Secrets(c.namespace).Delete(name+"-tls", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to delete secret %s-tls: %s", name, err)
	}

	return certChain, nil
}

func (c *certManagerClient) ensureCertificate(certName string, certValidTTLInSec int64,
	uriNames []string, csr *x509.CertificateRequest) (*certmanagerv1.Certificate, error) {
	log.Infof("cert-manager: creating certificate: (%s/%s)", c.namespace, certName)

	certObj := c.buildCertificate(certName, certValidTTLInSec, uriNames, csr)

	cert, err := c.cmClient.Certmanager().Certificates(c.namespace).Get(certName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}

		_, err := c.cmClient.Certmanager().Certificates(c.namespace).Create(certObj)
		if err != nil {
			return nil, err
		}
	}

	if certObj.Spec.IssuerRef.Kind != cert.Spec.IssuerRef.Kind ||
		certObj.Spec.IssuerRef.Name != cert.Spec.IssuerRef.Name ||
		certObj.Spec.SecretName != cert.Spec.SecretName ||
		!stringSliceCompare(certObj.Spec.DNSNames, cert.Spec.DNSNames) {

		log.Infof("cert-manager: updating certificate: (%s/%s)", c.namespace, certName)
		certObj.ResourceVersion = cert.ResourceVersion
		if certObj.ResourceVersion == "" {
			certObj.ResourceVersion = "0"
		}

		cert, err = c.cmClient.Certmanager().Certificates(c.namespace).Update(certObj)
		if err != nil {
			return nil, err
		}
	}

	return cert, nil
}

func stringSliceCompare(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for _, aa := range a {
		found := false

		for _, bb := range b {
			if aa == bb {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

func (c *certManagerClient) ensureSecret(name string, keyPEM []byte) error {
	secretName := name + "-tls"

	secObj := c.buildSecret(secretName, keyPEM)

	sec, err := c.kClient.CoreV1().Secrets(c.namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		log.Infof("cert-manager: creating secret: (%s/%s)", c.namespace, secretName)
		_, err := c.kClient.CoreV1().Secrets(c.namespace).Create(secObj)
		if err != nil {
			return err
		}

		return nil
	}

	pk, ok := sec.Data[corev1.TLSPrivateKeyKey]
	if !ok || !bytes.Equal(pk, keyPEM) {
		log.Infof("cert-manager: updating secret: (%s/%s)", c.namespace, secretName)
		secObj.ResourceVersion = sec.ResourceVersion
		if secObj.ResourceVersion == "" {
			secObj.ResourceVersion = "0"
		}

		_, err = c.kClient.CoreV1().Secrets(c.namespace).Update(secObj)
		return err
	}

	return nil
}

func (c *certManagerClient) buildCertificate(certName string, certValidTTLInSec int64,
	uriNames []string, csr *x509.CertificateRequest) *certmanagerv1.Certificate {
	return &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: c.namespace,
		},

		Spec: certmanagerv1.CertificateSpec{
			IssuerRef: certmanagerv1.ObjectReference{
				Kind: "Issuer",
				Name: issuerName,
			},

			Duration: &metav1.Duration{
				Duration: time.Second * time.Duration(certValidTTLInSec),
			},

			RenewBefore: &metav1.Duration{
				Duration: time.Second * time.Duration(certValidTTLInSec/4),
			},

			DNSNames:     uriNames,
			SecretName:   certName + "-tls",
			Organization: []string{"cluster.local"},
		},
	}
}

func (c *certManagerClient) buildSecret(name string, keyPEM []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyPEM,
			corev1.TLSCertKey:       nil,
		},
	}
}

func (c *certManagerClient) getCA() ([]byte, error) {
	s, err := c.kClient.CoreV1().Secrets(c.namespace).Get("istio-ca-secret", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	ca, ok := s.Data["ca-cert.pem"]
	if !ok {
		return nil, fmt.Errorf("failed to get ca from secret %s/%s", c.namespace, "istio-ca-secret")
	}

	return ca, nil
}
