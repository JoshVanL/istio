// Copyright 2019 Istio Authors
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
	"errors"
	"fmt"
	"strings"
	"time"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	restclient "k8s.io/client-go/rest"

	caClientInterface "istio.io/istio/security/pkg/nodeagent/caclient/interface"
	"istio.io/pkg/log"
)

const (
	waitTimout = time.Second * 20
)

type certmanagerClient struct {
	namespace string

	issuerName  string
	issuerKind  string
	issuerGroup string

	cmClient cmclient.Interface
}

func NewCertmanagerClient(namespace, issuerName, issuerKind, issuerGroup string, tls bool) (caClientInterface.Client, error) {
	log.Info("cert-manager: using cert-manager csr provider")

	if len(issuerName) == 0 || len(issuerKind) == 0 {
		return nil, fmt.Errorf("cert manager CA provider requires an Issuer Name and Kind, got IssuerName=%s IssuerKind=%s",
			issuerName, issuerKind)
	}

	log.Infof("cert-manager: using %s/%s:%s", issuerGroup, issuerKind, issuerName)

	restConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}
	restConfig.Insecure = !tls

	c := &certmanagerClient{
		namespace:   namespace,
		issuerName:  issuerName,
		issuerKind:  issuerKind,
		issuerGroup: issuerGroup,
	}

	c.cmClient, err = cmclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	log.Info("cert-manager: csr CA provider ready")

	return c, nil
}

func (c *certmanagerClient) CSRSign(ctx context.Context, csrPEM []byte, saToken string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {

	log.Info("cert-manager: csrSign called")

	// Decode CSR PEM to generate CR name
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		return nil, errors.New("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %s", err)
	}

	var name string
	if len(csr.URIs) > 0 {
		name = csr.URIs[0].String()
	} else if len(csr.DNSNames) > 0 {
		name = csr.DNSNames[0]
	} else {
		name = csr.Subject.String()
	}

	if name == "" {
		return nil, errors.New("failed to generate name from csr")
	}

	name = "istio-nodeagent." + name
	name = strings.ReplaceAll(name, ":", ".")
	name = strings.ReplaceAll(name, "/", ".")
	for strings.Contains(name, "..") {
		name = strings.ReplaceAll(name, "..", ".")
	}

	cr, err := c.cmClient.CertmanagerV1alpha1().CertificateRequests(c.namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		if !k8sErrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get CertificateRequest: %s", err)
		}

		cr, err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(c.namespace).Create(
			c.generateCertificateRequest(name, csrPEM, certValidTTLInSec),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create CertificateRequest: %s", err)
		}
	}

	if !bytes.Equal(cr.Spec.CSRPEM, csrPEM) {
		err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(c.namespace).Delete(name, &metav1.DeleteOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to old CertificateRequest: %s", err)
		}

		cr, err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(c.namespace).Create(
			c.generateCertificateRequest(name, csrPEM, certValidTTLInSec),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create CertificateRequest: %s", err)
		}
	}

	cr, err = c.waitForCertificateRequestReady(cr.Namespace, cr.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for CertificateRequest to become ready: %s", err)
	}

	return []string{string(cr.Status.Certificate), string(cr.Status.CA)}, nil
	//return []string{string(cr.Status.Certificate)}, nil
}

func (c *certmanagerClient) generateCertificateRequest(name string, csrPEM []byte, certValidTTLInSec int64) *v1alpha1.CertificateRequest {
	return &v1alpha1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.CertificateRequestSpec{
			CSRPEM: csrPEM,
			IsCA:   false,
			Duration: &metav1.Duration{
				Duration: time.Second * time.Duration(certValidTTLInSec),
			},
			IssuerRef: v1alpha1.ObjectReference{
				Name:  c.issuerName,
				Kind:  c.issuerKind,
				Group: c.issuerGroup,
			},
		},
	}
}

// WaitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func (c *certmanagerClient) waitForCertificateRequestReady(ns, name string) (*v1alpha1.CertificateRequest, error) {
	var cr *v1alpha1.CertificateRequest

	err := wait.PollImmediate(time.Second, waitTimout,
		func() (bool, error) {
			var err error

			cr, err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}

			isReady := apiutil.CertificateRequestHasCondition(cr, v1alpha1.CertificateRequestCondition{
				Type:   v1alpha1.CertificateRequestConditionReady,
				Status: v1alpha1.ConditionTrue,
			})

			if !isReady {
				return false, nil
			}

			return true, nil
		},
	)

	if err != nil {
		return nil, err
	}

	return cr, nil
}
