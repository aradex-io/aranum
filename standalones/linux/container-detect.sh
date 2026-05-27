#!/usr/bin/env bash
# container-detect.sh — am I in a container, and is escape feasible?
set -u

IN_CONTAINER=0
RUNTIME=""

[ -e /.dockerenv ]    && IN_CONTAINER=1 && RUNTIME="docker"
[ -e /run/.containerenv ] && IN_CONTAINER=1 && RUNTIME="${RUNTIME:-podman}"
if [ -r /proc/1/cgroup ] && grep -Eq 'docker|kubepods|containerd|lxc|garden' /proc/1/cgroup; then
    IN_CONTAINER=1
    RUNTIME="${RUNTIME:-$(grep -Eo 'docker|kubepods|containerd|lxc|garden' /proc/1/cgroup | head -1)}"
fi

if [ "$IN_CONTAINER" -eq 0 ]; then echo "[-] Not in a container (or runtime is hidden)"; exit 0; fi
echo "[+] Inside container, runtime: $RUNTIME"

echo
echo "=== /proc/1/cgroup ==="
cat /proc/1/cgroup 2>/dev/null

echo
echo "=== Capabilities ==="
[ -r /proc/self/status ] && grep ^Cap /proc/self/status
command -v capsh >/dev/null && capsh --print

echo
echo "=== Privileged? ==="
# Privileged containers have CapEff = ffffffff... (varies by kernel — 0x1ffffffffff is typical for 5.x)
EFF=$(grep ^CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
case "$EFF" in
    *ffffffffff*) echo "[!!] CapEff=$EFF — looks privileged" ;;
    *)            echo "CapEff=$EFF (limited)" ;;
esac

echo
echo "=== Sockets / sensitive mounts ==="
[ -S /var/run/docker.sock ] && echo "[!!] /var/run/docker.sock present"
[ -S /run/docker.sock ]      && echo "[!!] /run/docker.sock present"
[ -S /var/run/crio/crio.sock ] && echo "[!!] /var/run/crio/crio.sock present"
[ -S /run/containerd/containerd.sock ] && echo "[!!] containerd.sock present"
[ -S /var/run/kubelet.sock ] && echo "[!!] kubelet.sock present"
[ -d /host ]                 && echo "[!!] /host mount — host fs reachable"

echo
echo "=== Mounts (filtered) ==="
mount | grep -E 'proc|sys|cgroup|docker|overlay|bind|nsfs' | head -30

echo
echo "=== /dev sanity ==="
ls /dev/sd* /dev/nvme* 2>/dev/null

echo
echo "=== Service account tokens (Kubernetes) ==="
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && {
    echo "[!!] /var/run/secrets/kubernetes.io/serviceaccount/token"
    echo "Test: curl -sk -H \"Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/default/pods"
}

echo
echo "=== Escape candidates ==="
[ -w /sys/fs/cgroup/release_agent ] && echo "[!!] release_agent writable — classic cgroup escape"
grep -q 'cap_sys_admin' /proc/self/status 2>/dev/null && grep -q '/proc/sysrq' /proc 2>/dev/null
