package ladon

import "github.com/ory/keto/sdk/go/keto/swagger"

var (
	roles = map[string]Roles{
		"regex": {{
			ID:      "group1",
			Members: []string{"ken"},
		}, {
			ID:      "group2",
			Members: []string{"ken"},
		}, {
			ID:      "group3",
			Members: []string{"ken"},
		}},
		"exact": {{
			ID:      "group1",
			Members: []string{"ken"},
		}, {
			ID:      "group2",
			Members: []string{"ken"},
		}, {
			ID:      "group3",
			Members: []string{"ken"},
		}},
	}
	requests = map[string][]struct {
		req     swagger.OryAccessControlPolicyAllowedInput
		allowed bool
	}{
		"regex": {
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "other-thing",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "delete",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: true,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "forbidden_matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "allowed_matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: true,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "remoteip_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"remoteIPAddress": "192.168.0.5",
					},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "remoteip_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"remoteIPAddress": "192.168.10.5",
					},
				},
				allowed: true,
			},
		},
		"exact": {
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "other-thing",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "delete",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: true,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "forbidden_matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "allowed_matrix",
					Action:   "create",
					Context:  map[string]interface{}{},
				},
				allowed: true,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "remoteip_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"remoteIPAddress": "192.168.0.5",
					},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "remoteip_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"remoteIPAddress": "192.168.10.5",
					},
				},
				allowed: true,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "subject_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"owner": "alice",
					},
				},
				allowed: false,
			},
			{
				req: swagger.OryAccessControlPolicyAllowedInput{
					Subject:  "ken",
					Resource: "subject_matrix",
					Action:   "create",
					Context: map[string]interface{}{
						"owner": "ken",
					},
				},
				allowed: true,
			},
		},
	}
	policies = map[string]Policies{
		"regex": {
			Policy{
				ID:        "1",
				Subjects:  []string{"alice", "group1", "client"},
				Resources: []string{"matrix", "forbidden_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "2",
				Subjects:  []string{"siri"},
				Resources: []string{"<.*>"},
				Actions:   []string{"decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "3",
				Subjects:  []string{"group1"},
				Resources: []string{"forbidden_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Effect:    Deny,
			},
			Policy{
				ID:        "4",
				Subjects:  []string{"group1"},
				Resources: []string{"allowed_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "5",
				Subjects:  []string{"group1"},
				Resources: []string{"remoteip_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"remoteIPAddress": map[string]interface{}{
						"options": map[string]interface{}{
							"cidr": "192.168.0.0/16",
						},
						"type": "CIDRCondition",
					},
				},
				Effect: Deny,
			},
			Policy{
				ID:        "6",
				Subjects:  []string{"group1"},
				Resources: []string{"remoteip_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"remoteIPAddress": map[string]interface{}{
						"options": map[string]interface{}{
							"cidr": "192.168.10.0/24",
						},
						"type": "CIDRCondition",
					},
				},
				Effect: Allow,
			},
			Policy{
				ID:        "7",
				Subjects:  []string{"group1"},
				Resources: []string{"subject_matrix", "rn:hydra:token<.*>"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"owner": map[string]interface{}{
						"type": "EqualsSubjectCondition",
					},
				},
				Effect: Allow,
			},
		},
		"exact": {
			Policy{
				ID:        "1",
				Subjects:  []string{"alice", "group1", "client"},
				Resources: []string{"matrix", "forbidden_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "2",
				Subjects:  []string{"siri"},
				Resources: []string{""},
				Actions:   []string{"decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "3",
				Subjects:  []string{"group1"},
				Resources: []string{"forbidden_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Effect:    Deny,
			},
			Policy{
				ID:        "4",
				Subjects:  []string{"group1"},
				Resources: []string{"allowed_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Effect:    Allow,
			},
			Policy{
				ID:        "5",
				Subjects:  []string{"group1"},
				Resources: []string{"remoteip_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"remoteIPAddress": map[string]interface{}{
						"options": map[string]interface{}{
							"cidr": "192.168.0.0/16",
						},
						"type": "CIDRCondition",
					},
				},
				Effect: Deny,
			},
			Policy{
				ID:        "6",
				Subjects:  []string{"group1"},
				Resources: []string{"remoteip_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"remoteIPAddress": map[string]interface{}{
						"options": map[string]interface{}{
							"cidr": "192.168.10.0/24",
						},
						"type": "CIDRCondition",
					},
				},
				Effect: Allow,
			},
			Policy{
				ID:        "7",
				Subjects:  []string{"group1"},
				Resources: []string{"subject_matrix", "rn:hydra:token"},
				Actions:   []string{"create", "decide"},
				Conditions: map[string]interface{}{
					"owner": map[string]interface{}{
						"type": "EqualsSubjectCondition",
					},
				},
				Effect: Allow,
			},
		},
	}
)
