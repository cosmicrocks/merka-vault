### Kind
cat <<EOF | kind create cluster --name cosmic --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
  - role: worker
networking:
  disableDefaultCNI: true
EOF

### cilium
helm repo add cilium https://helm.cilium.io/
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/experimental/gateway.networking.k8s.io_grpcroutes.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.2.1/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml
helm upgrade --install cilium cilium/cilium --version 1.17.1 \
  --namespace cilium \
  --create-namespace \
  --set image.pullPolicy=IfNotPresent \
  --set ipam.mode=kubernetes \
  --set nodePort.enabled=true \
  --set gatewayAPI.enabled=true \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true

### kube-vip
kubectl apply -f https://kube-vip.io/manifests/rbac.yaml

kubectl create configmap --namespace kube-system kubevip --from-literal range-global=172.18.100.10-172.18.100.30
kubectl apply -f https://raw.githubusercontent.com/kube-vip/kube-vip-cloud-provider/main/manifest/kube-vip-cloud-controller.yaml
docker run --network host --rm ghcr.io/kube-vip/kube-vip:v0.8.9 manifest daemonset --services --inCluster --arp --interface eth0 | kubectl apply -f -

### cert-manager
kubectl create namespace cert-manager
helm repo add cert-manager https://charts.jetstack.io
helm upgrade --install --wait --timeout 1m --namespace cert-manager --create-namespace cert-manager cert-manager/cert-manager \
  --version 1.16.3 \
  --set installCRDs=true \
  --set config.apiVersion="controller.config.cert-manager.io/v1alpha1" \
  --set config.kind="ControllerConfiguration" \
  --set config.enableGatewayAPI=true

## vault
cat >vault-values.yaml <<EOF
server:

  extraSecretEnvironmentVars:
    - envName: VAULT_TOKEN
      secretName: unseal
      secretKey: token

  readinessProbe:
    enabled: true
    # For HA configuration and because we need to manually init the vault
    path: "/v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204"

  # Used to enable a livenessProbe for the pods
  livenessProbe:
    # For HA configuration and because we need to manually init the vault
    enabled: true
    path: "/v1/sys/health?standbyok=true"

  ha:
    enabled: true
    replicas: 3
    apiAddr: null
    clusterAddr: null
    raft:
      enabled: true
      setNodeId: false
      config: |
        ui = true
        listener "tcp" {
          tls_disable = 1
          address = "[::]:8200"
          cluster_address = "[::]:8201"
        }
        storage "raft" {
          path = "/vault/data"
          retry_join {
            leader_api_addr = "http://vault-0.vault-internal:8200"
          }
          retry_join {
            leader_api_addr = "http://vault-1.vault-internal:8200"
          }
          retry_join {
            leader_api_addr = "http://vault-2.vault-internal:8200"
          }
        }
        seal "transit" {
          address = "http://192.168.88.254:8200"
          disable_renewal = "false"
          key_name = "autounseal"
          mount_path = "transit/"
          tls_skip_verify = "true"
        }
        service_registration "kubernetes" {}
EOF

kubectl create namespace vault
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install --wait --timeout 1m --namespace vault --create-namespace vault hashicorp/vault --values vault-values.yaml
rm vault-values.yaml

kubectl apply -f - <<EOF
        apiVersion: gateway.networking.k8s.io/v1
        kind: Gateway
        metadata:
          name: services
          namespace: cilium
          annotations:
            cert-manager.io/issuer: vault-issuer
        spec:
          gatewayClassName: cilium
          listeners:
          - protocol: HTTPS
            name: https
            port: 443
            allowedRoutes:
              namespaces:
                from: All
            hostname: '*.cosmic.rocks'
            tls:
                certificateRefs:
                  - group: ''
                    kind: Secret
                    name: wildcard-cosmic-rocks
                mode: Terminate
          - protocol: HTTP
            port: 80
            name: services
            allowedRoutes:
              namespaces:
                from: All
EOF

kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: hubble-ui
  namespace: cilium
spec:
  hostnames:
  - hubble-ui.cosmic.local
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: services
    namespace: cilium
  rules:
  - backendRefs:
    - group: ""
      kind: Service
      name: hubble-ui
      port: 80
      weight: 1
    matches:
    - path:
        type: PathPrefix
        value: /
EOF

# docker run --network kind --rm curlimages/curl:8.12.1 -L -v -H "Host: hubble-ui.cosmic.local" http://172.18.100.10
