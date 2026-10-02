// Code generated from traust-contracts v0.48.1. DO NOT EDIT.

package types

type OperatorPrivProfile struct {
	ExampleOrTestManifestsExcluded map[string]interface{}        `json:"example_or_test_manifests_excluded,omitempty"`
	InstallModes                   map[string]interface{}        `json:"install_modes,omitempty"`
	Namespaces                     []string                      `json:"namespaces,omitempty"`
	Operatorgroups                 []map[string]interface{}      `json:"operatorgroups,omitempty"`
	RbacFlags                      *OperatorPrivProfileRbacFlags `json:"rbac_flags,omitempty"`
	RbacRules                      []map[string]interface{}      `json:"rbac_rules,omitempty"`
	Repo                           string                        `json:"repo"`
	SccRequests                    []map[string]interface{}      `json:"scc_requests,omitempty"`
	SccsShipped                    []map[string]interface{}      `json:"sccs_shipped,omitempty"`
	Summary                        OperatorPrivProfileSummary    `json:"summary"`
	Tier                           *string                       `json:"tier,omitempty"`
	Tier2RequiredVsGranted         map[string]interface{}        `json:"tier2_required_vs_granted,omitempty"`
	Workloads                      []Workload                    `json:"workloads,omitempty"`
}

type OperatorPrivProfileRbacFlags struct {
	EscalateBindImpersonate []string `json:"escalate_bind_impersonate,omitempty"`
	NodesAccess             []string `json:"nodes_access,omitempty"`
	PodsExec                []string `json:"pods_exec,omitempty"`
	RbacWrite               []string `json:"rbac_write,omitempty"`
	SecretsAccess           []string `json:"secrets_access,omitempty"`
	WildcardResources       []string `json:"wildcard_resources,omitempty"`
	WildcardVerbs           []string `json:"wildcard_verbs,omitempty"`
}

type OperatorPrivProfileSummary struct {
	ClusterScopedRules        *int     `json:"cluster_scoped_rules,omitempty"`
	DistinctClusterTriples    *int     `json:"distinct_cluster_triples,omitempty"`
	DistinctRuleTriples       *int     `json:"distinct_rule_triples,omitempty"`
	NoSccRequestRecorded      *bool    `json:"no_scc_request_recorded,omitempty"`
	PrivilegedOrHostWorkloads *int     `json:"privileged_or_host_workloads,omitempty"`
	RbacRules                 int      `json:"rbac_rules"`
	SccRequests               []string `json:"scc_requests,omitempty"`
	WildcardRules             *int     `json:"wildcard_rules,omitempty"`
	Workloads                 int      `json:"workloads"`
}

type Workload struct {
	Containers         []map[string]interface{} `json:"containers,omitempty"`
	HostIPC            *bool                    `json:"hostIPC,omitempty"`
	HostNetwork        *bool                    `json:"hostNetwork,omitempty"`
	HostPID            *bool                    `json:"hostPID,omitempty"`
	HostPathVolumes    *int                     `json:"hostPath_volumes,omitempty"`
	Kind               string                   `json:"kind"`
	Manifest           *string                  `json:"manifest,omitempty"`
	Name               interface{}              `json:"name,omitempty"`
	PodSecurityContext map[string]interface{}   `json:"pod_securityContext,omitempty"`
	ServiceAccountName interface{}              `json:"serviceAccountName,omitempty"`
}
