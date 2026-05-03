package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/terraform-provider-conjur/internal/conjur/api/mocks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPolicyBranchResource_Create(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPolicyBranchResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful branch creation",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("my-branch"),
				Branch: types.StringValue("data/test"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy",
					conjurapi.PolicyModePatch,
					"data/test",
					mock.AnythingOfType("*strings.Reader"),
				).Return(&conjurapi.PolicyResponse{}, nil)
			},
			expectedError: false,
		},
		{
			name: "API error during branch creation",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("error-branch"),
				Branch: types.StringValue("data/error"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy",
					conjurapi.PolicyModePatch,
					"data/error",
					mock.AnythingOfType("*strings.Reader"),
				).Return(nil, fmt.Errorf("error creating branch"))
			},
			expectedError: true,
			errorContains: "Unable to create policy branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPolicyBranchResource{
				client: mockV2,
			}

			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Schema: getPolicyBranchTestSchema(),
				},
			}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Schema: getPolicyBranchTestSchema(),
				},
			}

			ctx := context.Background()
			diags := req.Plan.Set(ctx, &tt.data)
			if diags.HasError() {
				t.Fatalf("Failed to set plan data: %v", diags)
			}
			r.Create(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestPolicyBranchResource_Read(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPolicyBranchResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "branch exists",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("valid"),
				Branch: types.StringValue("data/test"),
				FullID: types.StringValue("data/test/valid"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("ResourceExists", "policy:data/test/valid").Return(true, nil)
			},
		},
		{
			name: "branch does not exist, no error",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("nonexistent"),
				Branch: types.StringValue("data/test"),
				FullID: types.StringValue("data/test/nonexistent"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("ResourceExists", "policy:data/test/nonexistent").Return(false, nil)
			},
		},
		{
			name: "API error checking policy branch",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("error-branch"),
				Branch: types.StringValue("data/test"),
				FullID: types.StringValue("data/test/error-branch"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("ResourceExists", "policy:data/test/error-branch").Return(false, fmt.Errorf("connection refused"))
			},
			expectedError: true,
			errorContains: "Unable to read policy branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)

			r := &ConjurPolicyBranchResource{client: mockV2}

			req := resource.ReadRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPolicyBranchTestSchema(),
				},
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPolicyBranchTestSchema(),
				},
			}

			ctx := context.Background()
			req.State.Set(ctx, &tt.data)
			r.Read(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func TestPolicyBranchResource_Delete(t *testing.T) {
	tests := []struct {
		name          string
		data          ConjurPolicyBranchResourceModel
		setupMock     func(*mocks.MockClientV2)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful branch deletion",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("my-branch"),
				Branch: types.StringValue("data/test"),
				FullID: types.StringValue("data/test/my-branch"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy",
					conjurapi.PolicyModePatch,
					"data/test",
					mock.AnythingOfType("*strings.Reader"),
				).Return(&conjurapi.PolicyResponse{}, nil)
			},
		},
		{
			name: "API error during deletion",
			data: ConjurPolicyBranchResourceModel{
				Name:   types.StringValue("error-branch"),
				Branch: types.StringValue("data/test"),
				FullID: types.StringValue("data/test/error-branch"),
			},
			setupMock: func(mockV2 *mocks.MockClientV2) {
				mockV2.On("LoadPolicy",
					conjurapi.PolicyModePatch,
					"data/test",
					mock.AnythingOfType("*strings.Reader"),
				).Return(nil, fmt.Errorf("permission denied"))
			},
			expectedError: true,
			errorContains: "Unable to delete policy branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockV2 := mocks.NewMockClientV2(t)
			tt.setupMock(mockV2)
			r := &ConjurPolicyBranchResource{client: mockV2}

			req := resource.DeleteRequest{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPolicyBranchTestSchema(),
				},
			}
			resp := &resource.DeleteResponse{
				State: tfsdk.State{
					Raw:    tftypes.NewValue(tftypes.Object{}, nil),
					Schema: getPolicyBranchTestSchema(),
				},
			}

			ctx := context.Background()
			req.State.Set(ctx, &tt.data)
			r.Delete(ctx, req, resp)

			if tt.expectedError {
				assert.True(t, resp.Diagnostics.HasError())
				if tt.errorContains != "" {
					found := false
					for _, diag := range resp.Diagnostics.Errors() {
						if contains(diag.Summary(), tt.errorContains) || contains(diag.Detail(), tt.errorContains) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error to contain: %s", tt.errorContains)
				}
			} else {
				assert.False(t, resp.Diagnostics.HasError())
			}

			mockV2.AssertExpectations(t)
		})
	}
}

func getPolicyBranchTestSchema() schema.Schema {
	r := &ConjurPolicyBranchResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}
