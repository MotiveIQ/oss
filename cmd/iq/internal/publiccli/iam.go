package publiccli

import (
	"context"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
)

// iamVerb is one read-only ControlPlane verb. Verbs mirror the registered
// action vocabulary 1:1, so action is always the verb's CamelCase twin and
// permission errors are self-explanatory.
type iamVerb struct {
	use      string
	short    string
	action   string
	flag     string // required identifying flag; empty for list verbs
	flagHelp string
	call     func(context.Context, IAMClient, string) (proto.Message, error)
	view     func(proto.Message) iamView
}

func iamVerbs() []iamVerb {
	return []iamVerb{
		{
			use:    "list-roles",
			short:  "List IAM roles.",
			action: "iam:ListRoles",
			call: func(ctx context.Context, client IAMClient, _ string) (proto.Message, error) {
				return client.ListRoles(ctx, &iamv1.ListRolesRequest{})
			},
			view: func(message proto.Message) iamView {
				return iamRoleListView(message.(*iamv1.ListRolesResponse))
			},
		},
		{
			use:      "get-role",
			short:    "Show one IAM role.",
			action:   "iam:GetRole",
			flag:     "name",
			flagHelp: "Role name.",
			call: func(ctx context.Context, client IAMClient, name string) (proto.Message, error) {
				return client.GetRole(ctx, &iamv1.GetRoleRequest{Name: name})
			},
			view: func(message proto.Message) iamView {
				return iamRoleView(message.(*iamv1.Role))
			},
		},
		{
			use:    "list-policies",
			short:  "List IAM managed policies.",
			action: "iam:ListPolicies",
			call: func(ctx context.Context, client IAMClient, _ string) (proto.Message, error) {
				return client.ListPolicies(ctx, &iamv1.ListPoliciesRequest{})
			},
			view: func(message proto.Message) iamView {
				return iamPolicyListView(message.(*iamv1.ListPoliciesResponse))
			},
		},
		{
			use:      "get-policy",
			short:    "Show one IAM managed policy.",
			action:   "iam:GetPolicy",
			flag:     "name",
			flagHelp: "Policy name.",
			call: func(ctx context.Context, client IAMClient, name string) (proto.Message, error) {
				return client.GetPolicy(ctx, &iamv1.GetPolicyRequest{Name: name})
			},
			view: func(message proto.Message) iamView {
				return iamPolicyView(message.(*iamv1.Policy))
			},
		},
		{
			use:    "list-oidc-providers",
			short:  "List IAM OIDC providers.",
			action: "iam:ListOIDCProviders",
			call: func(ctx context.Context, client IAMClient, _ string) (proto.Message, error) {
				return client.ListOIDCProviders(ctx, &iamv1.ListOIDCProvidersRequest{})
			},
			view: func(message proto.Message) iamView {
				return iamOIDCProviderListView(message.(*iamv1.ListOIDCProvidersResponse))
			},
		},
		{
			use:      "get-oidc-provider",
			short:    "Show one IAM OIDC provider.",
			action:   "iam:GetOIDCProvider",
			flag:     "name",
			flagHelp: "OIDC provider name.",
			call: func(ctx context.Context, client IAMClient, name string) (proto.Message, error) {
				return client.GetOIDCProvider(ctx, &iamv1.GetOIDCProviderRequest{Name: name})
			},
			view: func(message proto.Message) iamView {
				return iamOIDCProviderView(message.(*iamv1.OIDCProvider))
			},
		},
		{
			use:    "list-resource-policies",
			short:  "List IAM resource policies.",
			action: "iam:ListResourcePolicies",
			call: func(ctx context.Context, client IAMClient, _ string) (proto.Message, error) {
				return client.ListResourcePolicies(ctx, &iamv1.ListResourcePoliciesRequest{})
			},
			view: func(message proto.Message) iamView {
				return iamResourcePolicyListView(message.(*iamv1.ListResourcePoliciesResponse))
			},
		},
		{
			use:      "get-resource-policy",
			short:    "Show the resource policy attached to one resource URN.",
			action:   "iam:GetResourcePolicy",
			flag:     "resource-urn",
			flagHelp: "Canonical resource URN.",
			call: func(ctx context.Context, client IAMClient, resourceURN string) (proto.Message, error) {
				return client.GetResourcePolicy(ctx, &iamv1.GetResourcePolicyRequest{ResourceUrn: resourceURN})
			},
			view: func(message proto.Message) iamView {
				return iamResourcePolicyView(message.(*iamv1.ResourcePolicy))
			},
		},
		{
			use:    "list-service-definitions",
			short:  "List IAM service definitions.",
			action: "iam:ListServiceDefinitions",
			call: func(ctx context.Context, client IAMClient, _ string) (proto.Message, error) {
				return client.ListServiceDefinitions(ctx, &iamv1.ListServiceDefinitionsRequest{})
			},
			view: func(message proto.Message) iamView {
				return iamServiceDefinitionListView(message.(*iamv1.ListServiceDefinitionsResponse))
			},
		},
		{
			use:      "get-service-definition",
			short:    "Show one IAM service definition.",
			action:   "iam:GetServiceDefinition",
			flag:     "name",
			flagHelp: "Service name (URN service segment).",
			call: func(ctx context.Context, client IAMClient, name string) (proto.Message, error) {
				return client.GetServiceDefinition(ctx, &iamv1.GetServiceDefinitionRequest{Name: name})
			},
			view: func(message proto.Message) iamView {
				return iamServiceDefinitionView(message.(*iamv1.ServiceDefinition))
			},
		},
	}
}

func (c *Command) iamCommand() *cobra.Command {
	options := iamOptions{Role: IAMHumanRoleURN}
	command := &cobra.Command{
		Use:   "iam",
		Short: "Read MotiveIQ IAM control-plane objects.",
		Long: "Read MotiveIQ IAM roles, policies, OIDC providers and service definitions.\n\n" +
			"Output defaults to JSON. Set IQ_DEFAULT_OUTPUT or --output to choose another\n" +
			"format. Use --query to select fields from the JSON response with JMESPath.",
		Example: "  iq iam list-roles\n" +
			"  iq iam list-roles --output table\n" +
			"  iq iam list-roles --query 'roles[].name' --output text\n" +
			"  iq iam get-role --name human",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_ = cmd.Help()
			return errUsage
		},
	}
	c.addIAMFlags(command, &options)
	for _, verb := range iamVerbs() {
		command.AddCommand(c.iamVerbCommand(verb, &options))
	}
	return command
}

func (c *Command) iamVerbCommand(verb iamVerb, options *iamOptions) *cobra.Command {
	argument := ""
	example := "  iq iam " + verb.use
	if verb.flag != "" {
		example += " --" + verb.flag + " <" + verb.flag + ">"
	}
	command := &cobra.Command{
		Use:               verb.use,
		Short:             verb.short,
		Example:           example + "\n" + example + " --output table",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := options.validate(); err != nil {
				return err
			}
			return c.runIAMVerb(cmd.Context(), verb, argument, *options)
		},
	}
	if verb.flag != "" {
		command.Flags().StringVar(&argument, verb.flag, "", verb.flagHelp)
		must(command.MarkFlagRequired(verb.flag))
		must(command.RegisterFlagCompletionFunc(verb.flag, cobra.NoFileCompletions))
	}
	return command
}

func (c *Command) runIAMVerb(ctx context.Context, verb iamVerb, argument string, options iamOptions) error {
	config, err := c.LoadSDKConfig(ctx, options.Role)
	if err != nil {
		return err
	}
	defer config.Close()
	client, err := c.NewIAMFromConfig(config)
	if err != nil {
		return err
	}
	response, err := verb.call(ctx, client, argument)
	if err != nil {
		return iamActionError(err, verb.action)
	}
	return c.printIAMResponse(options.outputOptions, verb.action, response, verb.view)
}

func iamRoleListView(response *iamv1.ListRolesResponse) iamView {
	rows := make([][]string, 0, len(response.GetRoles()))
	for _, role := range response.GetRoles() {
		rows = append(rows, []string{role.GetName(), role.GetUrn()})
	}
	return iamListView([]string{"name", "urn"}, rows)
}

func iamRoleView(role *iamv1.Role) iamView {
	return iamObjectView([]iamField{
		{"name", role.GetName()},
		{"urn", role.GetUrn()},
		{"max_session_duration_seconds", strconv.FormatInt(role.GetMaxSessionDurationSeconds(), 10)},
		{"attached_policy_urns", strings.Join(role.GetAttachedPolicyUrns(), " ")},
		{"create_time", formatIAMTime(role.GetCreateTime())},
		{"update_time", formatIAMTime(role.GetUpdateTime())},
		{"assume_role_policy_document", role.GetAssumeRolePolicyDocument()},
	}, "assume_role_policy_document")
}

func iamPolicyListView(response *iamv1.ListPoliciesResponse) iamView {
	rows := make([][]string, 0, len(response.GetPolicies()))
	for _, policy := range response.GetPolicies() {
		rows = append(rows, []string{policy.GetName(), policy.GetUrn()})
	}
	return iamListView([]string{"name", "urn"}, rows)
}

func iamPolicyView(policy *iamv1.Policy) iamView {
	return iamObjectView([]iamField{
		{"name", policy.GetName()},
		{"urn", policy.GetUrn()},
		{"default_version_number", strconv.FormatInt(policy.GetDefaultVersion().GetNumber(), 10)},
		{"content_hash", policy.GetDefaultVersion().GetContentHash()},
		{"create_time", formatIAMTime(policy.GetCreateTime())},
		{"update_time", formatIAMTime(policy.GetUpdateTime())},
		{"document_json", policy.GetDefaultVersion().GetDocumentJson()},
	}, "document_json")
}

func iamOIDCProviderListView(response *iamv1.ListOIDCProvidersResponse) iamView {
	rows := make([][]string, 0, len(response.GetProviders()))
	for _, provider := range response.GetProviders() {
		rows = append(rows, []string{provider.GetName(), provider.GetIssuer()})
	}
	return iamListView([]string{"name", "issuer"}, rows)
}

func iamOIDCProviderView(provider *iamv1.OIDCProvider) iamView {
	return iamObjectView([]iamField{
		{"name", provider.GetName()},
		{"urn", provider.GetUrn()},
		{"issuer", provider.GetIssuer()},
		{"discovery_url", provider.GetDiscoveryUrl()},
		{"allowed_algorithms", strings.Join(provider.GetAllowedAlgorithms(), " ")},
		{"allowed_audiences", strings.Join(provider.GetAllowedAudiences(), " ")},
		{"create_time", formatIAMTime(provider.GetCreateTime())},
		{"update_time", formatIAMTime(provider.GetUpdateTime())},
		{"issuer_ca_bundle", provider.GetIssuerCaBundle()},
	}, "issuer_ca_bundle")
}

func iamResourcePolicyListView(response *iamv1.ListResourcePoliciesResponse) iamView {
	rows := make([][]string, 0, len(response.GetResourcePolicies()))
	for _, policy := range response.GetResourcePolicies() {
		rows = append(rows, []string{policy.GetResourceUrn(), strconv.FormatInt(policy.GetRevisionNumber(), 10)})
	}
	return iamListView([]string{"resource_urn", "revision_number"}, rows)
}

func iamResourcePolicyView(policy *iamv1.ResourcePolicy) iamView {
	return iamObjectView([]iamField{
		{"resource_urn", policy.GetResourceUrn()},
		{"revision_number", strconv.FormatInt(policy.GetRevisionNumber(), 10)},
		{"content_hash", policy.GetContentHash()},
		{"create_time", formatIAMTime(policy.GetCreateTime())},
		{"update_time", formatIAMTime(policy.GetUpdateTime())},
		{"document_json", policy.GetDocumentJson()},
	}, "document_json")
}

func iamServiceDefinitionListView(response *iamv1.ListServiceDefinitionsResponse) iamView {
	rows := make([][]string, 0, len(response.GetServiceDefinitions()))
	for _, definition := range response.GetServiceDefinitions() {
		rows = append(rows, []string{
			definition.GetName(),
			strings.Join(iamResourceTypeNames(definition), " "),
			strings.Join(definition.GetActions(), " "),
		})
	}
	return iamListView([]string{"name", "resource_types", "actions"}, rows)
}

func iamServiceDefinitionView(definition *iamv1.ServiceDefinition) iamView {
	return iamObjectView([]iamField{
		{"name", definition.GetName()},
		{"resource_types", strings.Join(iamResourceTypeNames(definition), " ")},
		{"actions", strings.Join(definition.GetActions(), " ")},
		{"create_time", formatIAMTime(definition.GetCreateTime())},
		{"update_time", formatIAMTime(definition.GetUpdateTime())},
	})
}

// iamResourceTypeNames flattens the nested resource types to their names;
// their default resource policies are a document each, which only json
// renders faithfully.
func iamResourceTypeNames(definition *iamv1.ServiceDefinition) []string {
	names := make([]string, 0, len(definition.GetResourceTypes()))
	for _, resourceType := range definition.GetResourceTypes() {
		names = append(names, resourceType.GetName())
	}
	return names
}
