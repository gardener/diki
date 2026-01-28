## Minimal Required Permissions to Run Diki on your environment

In order to complete it's compliance checking, Diki will require permissions to read certain Kubernetes and Gardener resources, as well as to create and deploy `Pods` on the examined `Nodes`.
Below is a compiled list of RBAC-style rules that represent all required permissions for the tool. You may use this list to create your own RBAC resources.

```yaml
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - pods/exec
  verbs:
  - create
  - delete
  - get
  - watch
- apiGroups:
  - core.gardener.cloud
  resources:
  - cloudprofiles
  - namespacedcloudprofiles
  - shoots
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - configmaps
  - nodes
  - nodes/proxy
  - namespaces
  - pods
  - replicationcontrollers
  - services
  verbs:
  - get
  - list
- apiGroups:
  - apps
  resources:
  - daemonsets
  - deployments
  - replicasets
  - statefulsets
  verbs:
  - get
  - list
- apiGroups:
  - batch
  resources:
  - jobs
  - cronjobs   
  verbs:
  - get
  - list
- apiGroups:
  - autoscaling
  resources:
  - horizontalpodautoscalers
  verbs:
  - get
  - list
- apiGroups:
  - storage.k8s.io
  resources:
  - storageclasses
  verbs:
  - get
  - list
- apiGroups:
  - networking.k8s.io
  resources:
  - networkpolicies
  verbs:
  - get
  - list
- apiGroups:
  - rbac.authorization.k8s.io 
  resources:
  - roles
  - clusterroles
  verbs:
  - get
  - list
```