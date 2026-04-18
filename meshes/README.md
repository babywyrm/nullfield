# Service Mesh Overlays

Kustomize overlays that add mesh-specific annotations and CRDs on top of the base manifests in `deploy/manifests/`. Each mesh profile is independent of any integration target — they bolt onto any nullfield deployment.

## Profiles

| Mesh | Deploy command | What it adds |
|------|---------------|--------------|
| Istio | `kubectl apply -k meshes/istio/` | PeerAuthentication (STRICT mTLS), AuthorizationPolicy, Envoy sidecar annotations |
| Linkerd | `kubectl apply -k meshes/linkerd/` | Server, ServerAuthorization, opaque port + skip-inbound annotations |
| Cilium | `kubectl apply -k meshes/cilium/` | CiliumNetworkPolicy with L7 HTTP rules for proxy and admin ports |

## No mesh (bare)

If you don't run a service mesh, use the base manifests directly:

```bash
kubectl apply -f deploy/manifests/
```

## How it works

Each overlay references the base manifests and layers on mesh config:

```
meshes/istio/
  kustomization.yaml   # resources: [../../deploy/manifests], patches
  mesh-policy.yaml     # PeerAuthentication + AuthorizationPolicy
```

See [docs/mesh-integration.md](../docs/mesh-integration.md) for traffic flow diagrams, annotations, and gotchas per mesh.
