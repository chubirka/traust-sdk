// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

type AttackMapping struct {
	AttackVersion  string                 `json:"attack_version"`
	Attribution    string                 `json:"attribution"`
	CapabilityMap  map[string]interface{} `json:"capability_map"`
	CategoryMap    map[string]interface{} `json:"category_map"`
	Documentation  *string                `json:"documentation,omitempty"`
	MappingVersion string                 `json:"mapping_version"`
	Schema         *string                `json:"schema,omitempty"`
	Source         string                 `json:"source"`
}
