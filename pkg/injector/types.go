package injector

import "encoding/json"

// AdmissionReview mirrors the K8s admission.k8s.io/v1 AdmissionReview
// without pulling in k8s.io/api as a dependency.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string    `json:"uid"`
	Namespace string    `json:"namespace"`
	Object    RawObject `json:"object"`
}

type RawObject struct {
	Raw json.RawMessage `json:"raw,omitempty"`
}

func (r *RawObject) UnmarshalJSON(data []byte) error {
	r.Raw = data
	return nil
}

type AdmissionResponse struct {
	UID       string           `json:"uid"`
	Allowed   bool             `json:"allowed"`
	PatchType *string          `json:"patchType,omitempty"`
	Patch     json.RawMessage  `json:"patch,omitempty"`
}

// PodSpec is a minimal representation of a Pod for injection purposes.
type PodSpec struct {
	Metadata PodMeta     `json:"metadata"`
	Spec     PodSpecInner `json:"spec"`
}

type PodMeta struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type PodSpecInner struct {
	Containers []Container `json:"containers"`
	Volumes    []Volume    `json:"volumes,omitempty"`
}

type Container struct {
	Name  string          `json:"name"`
	Image string          `json:"image,omitempty"`
	Ports []ContainerPort `json:"ports,omitempty"`
}

type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
}

type Volume struct {
	Name string `json:"name"`
}

// PatchOp is a single JSON Patch operation (RFC 6902).
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}
