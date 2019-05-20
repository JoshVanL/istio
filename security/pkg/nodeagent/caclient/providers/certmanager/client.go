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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
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

func (c *certManagerClient) CSRSign(ctx context.Context, csrPEM, key []byte, saToken string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {

	keyPEM := make([]byte, len(key))
	copy(keyPEM, key)

	log.Info("cert-manager: csr sign called")

	//config := &restclient.Config{
	//	TLSClientConfig: c.restConfig.TLSClientConfig,
	//	APIPath:         c.restConfig.APIPath,
	//	Host:            c.restConfig.Host,
	//	BearerToken:     saToken,
	//}

	log.Infof("cert-manager: parsing certificate request")

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("certificate signing request is not properly encoded")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert-manager: failed to parse certificate request: %s\n%s", err, csrPEM)
	}

	dnsNames := csr.DNSNames
	for _, u := range csr.URIs {
		dnsNames = append(csr.DNSNames, u.String())
	}

	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("no dns names in CSR")
	}

	name := fmt.Sprintf("%s",
		strings.ReplaceAll(strings.ReplaceAll(
			dnsNames[0], "spiffe://", ""), "/", "-"))

	if err := c.ensureSecret(name, keyPEM); err != nil {
		return nil, err
	}

	if err := c.ensureCertificate(name, certValidTTLInSec, dnsNames, csr); err != nil {
		return nil, err
	}

	var tlsCert []byte
	var i int

	for {
		if i == 10 {
			return nil, fmt.Errorf(
				"failed to wait for certificate to become ready in secret %s",
				name)
		}

		time.Sleep(time.Second * 2)

		log.Info("waiting for certificate to become ready...")

		s, err := c.kClient.CoreV1().Secrets(c.namespace).Get(name+"-tls", metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		log.Infof(">%s", s.Data)

		cert, ok := s.Data[corev1.TLSCertKey]
		if ok && len(cert) > 0 {
			tlsCert = cert
			break
		}

		i++
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

	//err = c.cmClient.Certmanager().Certificates(c.namespace).Delete(name, nil)
	//if err != nil {
	//	return nil, err
	//}

	//err = c.kClient.Core().Secrets(c.namespace).Delete(name+"-tls", nil)
	//if err != nil {
	//	return nil, err
	//}

	log.Infof("cert-manager: got cert chain response: %s", certChain)
	log.Infof("cert-manager: using key: %s", keyPEM)

	return certChain, nil
}

func (c *certManagerClient) ensureCertificate(certName string, certValidTTLInSec int64,
	dnsNames []string, csr *x509.CertificateRequest) error {
	log.Infof("cert-manager: creating certificate: (%s/%s)", c.namespace, certName)

	certObj := c.buildCertificate(certName, certValidTTLInSec, dnsNames, csr)

	cert, err := c.cmClient.Certmanager().Certificates(c.namespace).Get(certName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		log.Infof("cert-manager: creating certificate: (%s/%s)", c.namespace, certName)

		_, err := c.cmClient.Certmanager().Certificates(c.namespace).Create(certObj)
		return err
	}

	//	if certObj.Spec.IssuerRef.Kind != cert.Spec.IssuerRef.Kind ||
	//		certObj.Spec.IssuerRef.Name != cert.Spec.IssuerRef.Name ||
	//		certObj.Spec.SecretName != cert.Spec.SecretName ||
	//		!stringSliceCompare(certObj.Spec.DNSNames, cert.Spec.DNSNames) {

	log.Infof("cert-manager: updating certificate: (%s/%s)", c.namespace, certName)
	certObj.ResourceVersion = cert.ResourceVersion

	_, err = c.cmClient.Certmanager().Certificates(c.namespace).Update(certObj)
	return err
	//}

	return nil
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

	_, err := c.kClient.CoreV1().Secrets(c.namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		log.Infof("cert-manager: creating secret: (%s/%s)", c.namespace, secretName)
		_, err := c.kClient.CoreV1().Secrets(c.namespace).Create(
			c.buildSecret(secretName, keyPEM))
		return err
	}

	//pk, ok := sec.Data[corev1.TLSPrivateKeyKey]
	//if !ok || !bytes.Equal(pk, keyPEM) {
	log.Infof("cert-manager: updating secret: (%s/%s)", c.namespace, secretName)

	_, err = c.kClient.CoreV1().Secrets(c.namespace).Update(
		c.buildSecret(secretName, keyPEM))
	return err
	//}

	return nil
}

func (c *certManagerClient) buildCertificate(certName string, certValidTTLInSec int64,
	dnsNames []string, csr *x509.CertificateRequest) *certmanagerv1.Certificate {
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

			DNSNames:   dnsNames,
			SecretName: certName + "-tls",
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
