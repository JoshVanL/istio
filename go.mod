module istio.io/istio

go 1.12

replace github.com/golang/glog => github.com/istio/glog v0.0.0-20190424172949-d7cfb6fa2ccd

replace k8s.io/klog => github.com/istio/klog v0.0.0-20190424230111-fb7481ea8bcf

replace github.com/spf13/viper => github.com/istio/viper v1.3.3-0.20190515210538-2789fed3109c

require (
	cloud.google.com/go v0.38.0
	code.cloudfoundry.org/copilot v0.0.0-20180808174356-6bade2a0677a
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	contrib.go.opencensus.io/exporter/stackdriver v0.6.0
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	fortio.org/fortio v1.3.0
	github.com/DataDog/datadog-go v2.2.0+incompatible
	github.com/Masterminds/semver v1.4.0 // indirect
	github.com/Masterminds/sprig v2.14.1+incompatible // indirect
	github.com/alicebob/gopher-json v0.0.0-20180125190556-5a6b3ba71ee6 // indirect
	github.com/alicebob/miniredis v0.0.0-20180201100744-9d52b1fc8da9
	github.com/aokoli/goutils v1.0.1 // indirect
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878 // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/aws/aws-sdk-go v1.13.24
	github.com/cactus/go-statsd-client v3.1.1+incompatible
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/circonus-labs/circonus-gometrics v2.3.1+incompatible
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/containerd/continuity v0.0.0-20190426062206-aaeac12a7ffc // indirect
	github.com/coreos/go-oidc v0.0.0-20180117170138-065b426bd416
	github.com/d4l3k/messagediff v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dchest/siphash v1.1.0 // indirect
	github.com/denisenkom/go-mssqldb v0.0.0-20190423183735-731ef375ac02 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0 // indirect
	github.com/docker/spdystream v0.0.0-20170912183627-bc6354cbbc29 // indirect
	github.com/dropbox/godropbox v0.0.0-20190501155911-5749d3b71cbe // indirect
	github.com/elazarl/go-bindata-assetfs v1.0.0 // indirect
	github.com/elazarl/goproxy v0.0.0-20190421051319-9d40249d3c2f // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190421051319-9d40249d3c2f // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/envoyproxy/go-control-plane v0.8.1
	github.com/evanphx/json-patch v4.2.0+incompatible
	github.com/facebookgo/stack v0.0.0-20160209184415-751773369052 // indirect
	github.com/facebookgo/stackerr v0.0.0-20150612192056-c2fcf88613f4 // indirect
	github.com/fluent/fluent-logger-golang v1.3.0
	github.com/fsnotify/fsnotify v1.4.7
	github.com/garyburd/redigo v1.6.0 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-logfmt/logfmt v0.4.0 // indirect
	github.com/go-redis/redis v6.10.2+incompatible
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gocql/gocql v0.0.0-20190423091413-b99afaf3b163 // indirect
	github.com/gogo/googleapis v1.1.0
	github.com/gogo/protobuf v1.2.1
	github.com/gogo/status v1.0.3
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20180203143532-66deaeb636df // indirect
	github.com/golang/protobuf v1.3.1
	github.com/golang/sync v0.0.0-20180314180146-1d60e4601c6f
	github.com/google/cel-go v0.2.0
	github.com/google/go-cmp v0.3.0
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/googleapis/gax-go v2.0.0+incompatible
	github.com/googleapis/gax-go/v2 v2.0.4
	github.com/googleapis/gnostic v0.1.0 // indirect
	github.com/gophercloud/gophercloud v0.2.0 // indirect
	github.com/gorilla/mux v1.7.1
	github.com/gorilla/websocket v1.2.0
	github.com/grpc-ecosystem/go-grpc-middleware v0.0.0-20190222133341-cfaf5686ec79
	github.com/grpc-ecosystem/go-grpc-prometheus v0.0.0-20170330212424-2500245aa611
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20171214222146-0e7658f8ee99
	github.com/hashicorp/consul v1.3.0
	github.com/hashicorp/go-hclog v0.9.0 // indirect
	github.com/hashicorp/go-memdb v1.0.1 // indirect
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/memberlist v0.1.3 // indirect
	github.com/hashicorp/serf v0.8.1 // indirect
	github.com/hashicorp/vault v0.10.0
	github.com/howeyc/fsnotify v0.9.0
	github.com/huandu/xstrings v1.0.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/jetstack/cert-manager v0.9.0-alpha.0
	github.com/juju/errors v0.0.0-20190207033735-e65537c515d7 // indirect
	github.com/juju/loggo v0.0.0-20190212223446-d976af380377 // indirect
	github.com/juju/testing v0.0.0-20190429233213-dfc56b8c09fc // indirect
	github.com/keybase/go-crypto v0.0.0-20190416182011-b785b22cc757 // indirect
	github.com/lestrrat-go/jwx v0.9.0
	github.com/lib/pq v1.1.1 // indirect
	github.com/lukechampine/freeze v0.0.0-20160818180733-f514e08ae5a0
	github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/natefinch/lumberjack v2.0.0+incompatible
	github.com/onsi/gomega v1.5.0
	github.com/open-policy-agent/opa v0.8.2
	github.com/openshift/api v0.0.0-20190322043348-8741ff068a47
	github.com/opentracing/opentracing-go v1.0.2
	github.com/openzipkin/zipkin-go v0.1.6
	github.com/pkg/errors v0.8.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/pquerna/cachecontrol v0.0.0-20180306154005-525d0eb5f91d // indirect
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/prometheus/client_model v0.0.0-20190115171406-56726106282f
	github.com/prometheus/common v0.2.0
	github.com/prometheus/prom2json v1.1.0
	github.com/satori/go.uuid v1.2.0
	github.com/signalfx/com_signalfx_metrics_protobuf v0.0.0-20170330202426-93e507b42f43
	github.com/signalfx/gohistogram v0.0.0-20160107210732-1ccfd2ff5083 // indirect
	github.com/signalfx/golib v1.1.6
	github.com/spf13/cobra v0.0.4
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.3.0
	github.com/uber/jaeger-client-go v0.0.0-20190228190846-ecf2d03a9e80
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180206001645-7af743e8ec84 // indirect
	github.com/yl2chen/cidranger v0.0.0-20180214081945-928b519e5268
	github.com/yuin/gopher-lua v0.0.0-20180316054350-84ea3a3c79b3 // indirect
	go.opencensus.io v0.21.0
	go.uber.org/atomic v1.4.0
	go.uber.org/multierr v1.1.0
	go.uber.org/zap v1.10.0
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980
	golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/tools v0.0.0-20190614205625-5aca471b1d59
	google.golang.org/api v0.4.0
	google.golang.org/genproto v0.0.0-20190502173448-54afdca5d873
	google.golang.org/grpc v1.20.1
	gopkg.in/d4l3k/messagediff.v1 v1.2.1
	gopkg.in/logfmt.v0 v0.3.0 // indirect
	gopkg.in/square/go-jose.v2 v2.0.0-20180411045311-89060dee6a84
	gopkg.in/stack.v1 v1.7.0 // indirect
	gopkg.in/yaml.v2 v2.2.2
	istio.io/api v0.0.0-20190708200418-70f6e4eada00
	istio.io/pkg v0.0.0-20190624144336-268695a9d878
	k8s.io/api v0.0.0-20190703205437-39734b2a72fe
	k8s.io/apiextensions-apiserver v0.0.0-20190221221350-bfb440be4b87
	k8s.io/apimachinery v0.0.0-20190703205208-4cfb76a8bf76
	k8s.io/cli-runtime v0.0.0-20190704050804-7ea68ffa02c5
	k8s.io/client-go v0.0.0-20190704045512-07281898b0f0
	k8s.io/helm v2.9.1+incompatible
	sigs.k8s.io/yaml v1.1.0
)
