package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api"
	internalpolicy "github.com/cyberark/terraform-provider-conjur/internal/policy"
	"github.com/doodlesbykumbi/conjur-policy-go/pkg/conjurpolicy"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gopkg.in/yaml.v3"
)

var _ resource.Resource = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithConfigure = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithImportState = &ConjurPolicyBranchResource{}
var _ resource.ResourceWithValidateConfig = &ConjurPolicyBranchResource{}

func NewConjurPolicyBranchResource() resource.Resource {
	return &ConjurPolicyBranchResource{}
}

type ConjurPolicyBranchResource struct {
	client api.ClientV2
}

type ConjurPolicyBranchResourceModel struct {
	Name   types.String `tfsdk:"name"`
	Branch types.String `tfsdk:"branch"`
	FullID types.String `tfsdk:"full_id"`
}

func (r *ConjurPolicyBranchResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_branch"
}

func (r *ConjurPolicyBranchResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "CyberArk Secrets Manager Policy Branch resource",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Policy branch name (leaf)",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				MarkdownDescription: "Parent policy path",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"full_id": schema.StringAttribute{
				MarkdownDescription: "Computed identifier: `<branch>/<name>`",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *ConjurPolicyBranchResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ValidateNonEmpty(data.Name, &resp.Diagnostics, "Policy branch name")
	ValidateBranch(data.Branch, &resp.Diagnostics, "branch")
}

func (r *ConjurPolicyBranchResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(api.ClientV2)
	if !ok {
		AddUnexpectedConfigureTypeError(&resp.Diagnostics, "api.ClientV2", req.ProviderData)
		return
	}
	r.client = client
}

func (r *ConjurPolicyBranchResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Creating policy branch via policy API: parent=%q, leaf=%q", parent, leaf))

	policyYAML, err := buildBranchCreatePolicy(leaf)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Policy", fmt.Sprintf("Unable to build policy for branch %q: %s", leaf, err))
		return
	}

	if err := internalpolicy.ApplyPolicy(r.client, policyYAML, parent); err != nil {
		tflog.Error(ctx, fmt.Sprintf("ApplyPolicy failed for branch creation: %s", err))
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create policy branch: %s", err))
		return
	}

	data.Name = types.StringValue(leaf)
	data.Branch = types.StringValue(parent)
	data.FullID = types.StringValue(fullID)

	tflog.Trace(ctx, "Created policy branch resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConjurPolicyBranchResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Reading branch: parent=%q, leaf=%q, fullID=%q", parent, leaf, fullID))

	exists, err := r.client.ResourceExists("policy:" + fullID)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read policy branch %q: %s", fullID, err))
		return
	}

	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}

	data.Name = types.StringValue(leaf)
	data.Branch = types.StringValue(parent)
	data.FullID = types.StringValue(fullID)

	tflog.Trace(ctx, "Read policy branch resource")
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Not supported - requires resource recreation via planmodifiers since there's no PATCH support in the API
func (r *ConjurPolicyBranchResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddWarning(
		"Update will delete child resources!",
		"Recreating a policy branch will remove all resources under that branch path. Applying this change may therefore delete variables, hosts, or other resources under the branch.",
	)
}

func (r *ConjurPolicyBranchResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		AddProviderClientNotConfiguredWarning(&resp.Diagnostics)
		return
	}
	var data ConjurPolicyBranchResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent := strings.Trim(data.Branch.ValueString(), "/")
	leaf := strings.Trim(data.Name.ValueString(), "/")
	fullID := joinPath(parent, leaf)

	tflog.Debug(ctx, fmt.Sprintf("Deleting branch: parent=%q, leaf=%q, fullID=%q", parent, leaf, fullID))

	policyYAML, err := buildBranchDeletePolicy(leaf)
	if err != nil {
		resp.Diagnostics.AddError("Error Building Policy", fmt.Sprintf("Unable to build delete policy for branch %q: %s", leaf, err))
		return
	}

	if err := internalpolicy.ApplyPolicy(r.client, policyYAML, parent); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete policy branch %q: %s", fullID, err))
		return
	}

	tflog.Trace(ctx, "Deleted policy branch resource")
	resp.State.RemoveResource(ctx)
}

func (r *ConjurPolicyBranchResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.Trim(req.ID, "/")
	if id == "" || !strings.Contains(id, "/") {
		resp.Diagnostics.AddError("Unexpected Import Identifier", "Expected format: <parent-branch>/<name>, e.g. apps/my-app/backend")
		return
	}

	parent, name := splitParentAndName(id)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("branch"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("full_id"), id)...)
}

func buildBranchCreatePolicy(leaf string) (string, error) {
	p := conjurpolicy.Policy{Id: leaf}
	statements := conjurpolicy.PolicyStatements{p}
	yamlBytes, err := yaml.Marshal(statements)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

func buildBranchDeletePolicy(leaf string) (string, error) {
	del := conjurpolicy.Delete{
		Record: conjurpolicy.ResourceRef{
			Kind: conjurpolicy.KindPolicy,
			Id:   leaf,
		},
	}
	statements := conjurpolicy.PolicyStatements{del}
	yamlBytes, err := yaml.Marshal(statements)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

func joinPath(parent, leaf string) string {
	parent = strings.Trim(parent, "/")
	leaf = strings.Trim(leaf, "/")
	if parent == "" {
		return leaf
	}
	return parent + "/" + leaf
}

func splitParentAndName(id string) (string, string) {
	id = strings.Trim(id, "/")
	idx := strings.LastIndex(id, "/")
	if idx < 0 {
		return "", id
	}
	return id[:idx], id[idx+1:]
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}
