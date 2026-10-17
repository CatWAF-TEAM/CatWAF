# Docker autoconfiguration and Kubernetes ingress

Both controllers are part of CatWAF Free's Node.js backend. Use the Full install
(which is also free); Lite does not run the backend or reconciliation scheduler.
The dashboard entry is **System → Docker & Kubernetes**. Controllers are disabled
by default. Set **Protected sites → Maximum protected sites** to your intended
budget (1–1000 hosts; default 1), preview, then enable reconciliation.

Controllers own separate route sets and preserve each other's routes. They
inherit global WAF rules, bans, challenge policy and site protections. Docker
labels can override the documented subset of policy for their own host. Mixed
policies for paths on one host are rejected. Labels are trusted configuration:
only trusted operators should have permission to create labelled containers.

A complete inventory is validated before publishing. Missing services, malformed
labels, conflicting routes, invalid certificates, permission failures and API
outages retain the previous configuration. Changes use the existing SQLite /
Caddy transaction, with validation and rollback. Unchanged inventories do not
reload. A successful preview does not prove network reachability or TLS issuance.

## Docker

The optional metadata bridge reads one fixed Docker API endpoint and exports
container IDs, names, CatWAF labels and network addresses. It has no TCP listener,
does not forward arbitrary Docker requests, and drops environment variables and
mounts. The backend receives only this socket. The bridge still holds a powerful
Docker socket: isolate its shared volume and image. A `:ro` socket mount alone is
not a Docker API permission boundary.

```bash
export DOCKER_GID="$(stat -c %g /var/run/docker.sock)"
docker compose -f docker-compose.yml -f compose.autoconf.yml up -d --build
```

For a custom label prefix, set `CATWAF_LABEL_PREFIX` on the bridge to the same
value as `autoconf.label_prefix`. Host installs may instead use the Docker CLI;
that requires the backend account to have Docker access.

Attach your application and Caddy to the same Docker network. Do not publish the
origin's port on the host. Add these labels to the application (replace the
network with its actual Docker network name, including any Compose prefix):

```yaml
labels:
  catwaf.enable: 'true'
  catwaf.host: app.example.com
  catwaf.port: '3000'
  catwaf.network: myproject_default
  catwaf.path: /
  catwaf.tls: auto
  catwaf.paranoia: '2'
  catwaf.headers: strict
```

`tls=auto` uses Caddy ACME; public DNS and ports 80/443 must reach this instance.
For an HTTP-only local test use `tls=off`. Backend `protocol` accepts `http`,
`https` or `grpc` (cleartext HTTP/2). HTTPS backend certificates are verified;
configure the expected server name and trusted CA in Proxy settings if needed.
The `methods`, `websockets`, `waf` and `bypass` labels are also supported; inspect
`GET /api/autoconf` for the complete label schema. `waf=off` and bypass paths
explicitly reduce inspection and should only be set deliberately.

Set `autoconf.enabled=true`. Set `remove_orphans=true` to remove routes for stopped
or deleted containers; its compatibility default is false. Scans run every
300 seconds by default, configurable down to 30 seconds. A malformed or partial
inventory is a failure, not an empty desired state. With orphan removal disabled,
old container IPs can become stale: prefer removal for ephemeral applications.

The base Compose example still includes the demo catch-all site. Replace that
site with your intended default response when using autoconfiguration in
production; host-specific managed routes do not remove hand-written sites.

## Kubernetes

[deploy/kubernetes/catwaf.yaml](../deploy/kubernetes/catwaf.yaml) supplies a
single-replica deployment, persistent volume, explicit service-account token
projection, namespace RBAC, IngressClass and public Service. Build images from the
same checkout and load them into your cluster's runtime or push to your own
registry and update the manifest's image names:

```bash
docker build -t catwaf-backend:1.0.2 .
docker build -f docker/Caddy.Dockerfile -t catwaf-caddy:1.0.2 .
kubectl create namespace catwaf --dry-run=client -o yaml | kubectl apply -f -
secret_file=$(mktemp)
chmod 600 "$secret_file"
openssl rand -hex 32 > "$secret_file"
kubectl -n catwaf create secret generic catwaf-secrets --from-file=JWT_SECRET="$secret_file"
rm -f "$secret_file"
kubectl apply -f deploy/kubernetes/catwaf.yaml
kubectl -n catwaf rollout status deployment/catwaf
kubectl -n catwaf exec -it deploy/catwaf -c backend -- node bin/catwaf.js user add admin --role admin
kubectl -n catwaf port-forward deploy/catwaf 8081:8081
```

Open `http://127.0.0.1:8081`. The dashboard and Node API bind only to the Pod's
loopback; the Service publishes only the protected HTTP/HTTPS ports. Set
`kubernetes.namespace=catwaf`, `kubernetes.enabled=true`, and the desired site
capacity. Keep jobs enabled. The effective interval is at least the scheduler's
15-second tick. Install your app as a ClusterIP Service in that namespace and
adapt [ingress.example.yaml](../deploy/kubernetes/ingress.example.yaml).

The controller implements `networking.k8s.io/v1` Ingress with:

- An explicit `ingressClassName: catwaf` (or the legacy class annotation), with
  the IngressClass controller set to `catwaf.com/ingress-controller`.
- Host rules, `Exact` and segment-bounded `Prefix` paths, longest path first and
  Exact before Prefix on ties. Routing does not strip prefixes.
- Same-namespace ClusterIP Services, named/numbered TCP ports, IPv4 and IPv6.
- Same-namespace `kubernetes.io/tls` Secrets. Certificates must match the host,
  private key and validity period. Certificate rotation publishes new immutable
  assets; invalid updates retain the last good generation.
- `catwaf.com/backend-protocol: http|https|grpc`.
- Paginated, authenticated API reads with CA validation, token rereading,
  deadlines, body limits, and removal of routes after successful deletion reads.

The manifest grants **no Secret API permissions**. It explicitly mounts `app-tls`
read-only at `/run/catwaf-tls/app-tls`, visible only to the backend. For each
additional TLS Secret, add a named Secret volume and a backend-only mount at
`/run/catwaf-tls/<secret-name>`. Keep `CATWAF_K8S_TLS_DIR=/run/catwaf-tls` and do
not use `subPath` for these mounts: kubelet must be able to rotate them. Each
reconcile reads the certificate and key from the same atomic `..data` generation.
Allow for kubelet projection delay plus the controller polling interval.

The API token has a requested 600-second lifetime and is projected with mode
0440 at `/run/catwaf-kubernetes`, only in the backend. Automatic token mounting
is disabled on both the Pod and ServiceAccount. The controller rereads the token
for each request. Host/custom deployments without `CATWAF_K8S_TLS_DIR` retain the
older explicit Secret-GET mode; that mode requires separately granted RBAC.
Use a dedicated namespace containing only trusted applications. The controller
cannot mutate Kubernetes resources.
It does not update Ingress status or request certificates from cert-manager.
Use cert-manager or another issuer to populate the referenced Secrets.

This version intentionally rejects default backends, hostless rules,
`ImplementationSpecific` paths, ExternalName/headless Services and cross-namespace
backends. It is a polling controller, not a Gateway API controller. Keep one
replica: SQLite, pending challenges and configuration publication are not an HA
cluster protocol. The example requires a dynamic storage class and a working
LoadBalancer implementation (or change the Service type for your environment).
`externalTrafficPolicy: Local` preserves source addresses where the provider
supports it; verify the observed client IP before using IP-based controls.

## Operational limits and validation

Upload scanning currently requires one upstream per managed host. Managed hosts
require reverse-proxy origin mode. An enabled site feature that the installed
Caddy cannot render rejects reconciliation instead of being silently omitted.
Global custom rules apply to every managed host. Raw configuration remains an
administrator escape hatch and can override generated behavior.

Disabling a controller stops reconciliation and preserves its last working
routes. Remove its resources while enabled and reconcile successfully to remove
routes. Docker orphan removal must be enabled for this. Full database backups
include managed state and TLS secrets; protect those backups. Settings-only
exports do not carry controller inventories or TLS Secret material.

Run `npm run test:parity` and `npm run test:orchestration`. The latter requires
Linux, OpenSSL and the existing upstream Caddy/Coraza binary. It exercises real
proxy requests and local protocol fixtures. These tests do not constitute
Kubernetes conformance, production-cluster validation, live provider-account
verification or BunkerWeb reliability equivalence. See
[feature validation](feature-validation-2026-10-17.md),
[feature coverage](bunkerweb-feature-coverage.md) and the existing
[latest validation and release blockers](reliability-followup-2026-10-17.md).

For the real Kubernetes test, create an empty disposable kind cluster named
`catwaf-<test-name>` with a separate kubeconfig, build and load both images, then
run `npm run test:kubernetes` with `CATWAF_K8S_TEST_KUBECONFIG`,
`CATWAF_K8S_BACKEND_IMAGE` and `CATWAF_K8S_CADDY_IMAGE` set. `KUBECTL` can select
the kubectl binary. The test refuses an unrelated context or existing fixture
objects. It exercises routing, real RBAC denials, certificate rotation, audit
rotation, controller outages, application rollout and persistent Pod recreation.
It removes its namespace and cluster-scoped fixture objects by default. Delete
the disposable cluster afterward. The CI workflow includes this check.

For the real Docker lifecycle check, build `docker/Metadata.Dockerfile` as
`catwaf-metadata:test`, then run `npm run test:docker-autoconf` on a local Linux
Docker host. The test creates uniquely named containers and an internal network,
checks protected routing, outage retention, recreation and deletion, and removes
its containers/network afterward. It publishes no host ports. It requires
permission to share its temporary bind directory and access the Docker socket.
