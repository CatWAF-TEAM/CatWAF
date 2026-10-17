---
id: orchestration
title: Docker autoconfiguration and Kubernetes ingress
keywords: [docker, autoconf, kubernetes, k8s, ingress, ingressclass, labels, multisite, controller, routes, tls secret]
questions:
  - How do I enable Docker autoconfiguration?
  - How do I use CatWAF as a Kubernetes ingress controller?
  - Can CatWAF Free protect multiple sites?
  - Why did my container routes fail to update?
related: [editions, getting-started, troubleshooting]
actions: []
---

CatWAF Free includes Node.js Docker and Kubernetes controllers in the Full installation. Open System → Docker & Kubernetes. Set Protected sites / Maximum protected sites to your capacity (1–1000, default 1). Enable only the controller you need, preview its routes, then reconcile. Both use validated atomic configuration transactions and retain the last working routes after failed reads or validation.

Docker needs a shared proxy/application network and catwaf.enable=true, catwaf.host, catwaf.port labels. Specify catwaf.network when multiple networks exist. tls=auto enables Caddy ACME, tls=off is HTTP. The optional compose.autoconf.yml adds a read-only metadata bridge; the application backend never gets the Docker engine socket. Set DOCKER_GID to the engine socket's group. Set remove_orphans=true for deleted/stopped containers to lose their routes; default false retains them.

Kubernetes requires an explicit catwaf IngressClass, a namespace-scoped service account, ClusterIP Service backends, and Exact or Prefix paths. TLS uses same-namespace kubernetes.io/tls Secrets. The controller validates certificate host, key and dates and reloads rotations. Unsupported resource types, wrong classes, permission failures and API outages are not silently accepted. It polls rather than watches, does not update Ingress status, and supports one replica. The supplied example uses namespace catwaf; set the controller namespace accordingly. The dashboard is available only through loopback/port-forward.

The supplied Kubernetes manifest grants no Secret API access. TLS Secrets must be explicitly mounted read-only in the backend at /run/catwaf-tls/<secret-name>; app-tls is included. Do not use subPath mounts for Secrets. The backend reads the key and certificate from one kubelet generation. Projected token credentials are backend-only with a requested 600-second lifetime. Allow kubelet projection and polling time for updates.

See docs/orchestration.md and deploy/kubernetes for setup. Disabling discovery keeps the last good routes; delete resources and reconcile while enabled to remove them. Site rules and challenge policy are global, with a limited Docker label override set. Audit retention now waits for writer retirement and follows late records; the container image includes a private Node.js writer observer. Do not claim complete BunkerWeb parity or a clean reliability release: reload resets and the dependency-module advisory remain unresolved. See docs/reliability-followup-2026-10-17.md for current measured results. CatAI can explain these settings but has no controller-deployment action.
