// Copyright 2020 The LUCI Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.21.7
// source: go.chromium.org/luci/resultdb/proto/v1/test_metadata.proto

package resultpb

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Information about a test metadata.
type TestMetadataDetail struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Can be used to refer to a test metadata, e.g. in ResultDB.QueryTestMetadata
	// RPC.
	// Format:
	// "projects/{PROJECT}/refs/{REF_HASH}/tests/{URL_ESCAPED_TEST_ID}".
	// where URL_ESCAPED_TEST_ID is test_id escaped with
	// https://golang.org/pkg/net/url/#PathEscape. See also https://aip.dev/122.
	//
	// Output only.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The LUCI project.
	Project string `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`
	// A unique identifier of a test in a LUCI project.
	// Refer to TestResult.test_id for details.
	TestId string `protobuf:"bytes,3,opt,name=test_id,json=testId,proto3" json:"test_id,omitempty"`
	// Hexadecimal encoded hash string of the source_ref.
	// A given source_ref always hashes to the same ref_hash value.
	RefHash string `protobuf:"bytes,12,opt,name=ref_hash,json=refHash,proto3" json:"ref_hash,omitempty"`
	// A reference in the source control system where the test metadata comes from.
	SourceRef *SourceRef `protobuf:"bytes,4,opt,name=source_ref,json=sourceRef,proto3" json:"source_ref,omitempty"`
	// Test metadata content.
	TestMetadata *TestMetadata `protobuf:"bytes,5,opt,name=testMetadata,proto3" json:"testMetadata,omitempty"`
}

func (x *TestMetadataDetail) Reset() {
	*x = TestMetadataDetail{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestMetadataDetail) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestMetadataDetail) ProtoMessage() {}

func (x *TestMetadataDetail) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestMetadataDetail.ProtoReflect.Descriptor instead.
func (*TestMetadataDetail) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{0}
}

func (x *TestMetadataDetail) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TestMetadataDetail) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *TestMetadataDetail) GetTestId() string {
	if x != nil {
		return x.TestId
	}
	return ""
}

func (x *TestMetadataDetail) GetRefHash() string {
	if x != nil {
		return x.RefHash
	}
	return ""
}

func (x *TestMetadataDetail) GetSourceRef() *SourceRef {
	if x != nil {
		return x.SourceRef
	}
	return nil
}

func (x *TestMetadataDetail) GetTestMetadata() *TestMetadata {
	if x != nil {
		return x.TestMetadata
	}
	return nil
}

// Information about a test.
type TestMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The original test name.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Where the test is defined, e.g. the file name.
	// location.repo MUST be specified.
	Location *TestLocation `protobuf:"bytes,2,opt,name=location,proto3" json:"location,omitempty"`
	// The issue tracker component associated with the test, if any.
	// Bugs related to the test may be filed here.
	BugComponent *BugComponent `protobuf:"bytes,3,opt,name=bug_component,json=bugComponent,proto3" json:"bug_component,omitempty"`
	// Identifies the schema of the JSON object in the properties field.
	// Use the fully-qualified name of the source protocol buffer.
	// eg. chromiumos.test.api.TestCaseInfo
	// ResultDB will *not* validate the properties field with respect to this
	// schema. Downstream systems may however use this field to inform how the
	// properties field is interpreted.
	PropertiesSchema string `protobuf:"bytes,4,opt,name=properties_schema,json=propertiesSchema,proto3" json:"properties_schema,omitempty"`
	// Arbitrary JSON object that contains structured, domain-specific properties
	// of the test.
	//
	// The serialized size must be <= 4096 bytes.
	//
	// If this field is specified, properties_schema must also be specified.
	Properties *structpb.Struct `protobuf:"bytes,5,opt,name=properties,proto3" json:"properties,omitempty"`
}

func (x *TestMetadata) Reset() {
	*x = TestMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestMetadata) ProtoMessage() {}

func (x *TestMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestMetadata.ProtoReflect.Descriptor instead.
func (*TestMetadata) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{1}
}

func (x *TestMetadata) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TestMetadata) GetLocation() *TestLocation {
	if x != nil {
		return x.Location
	}
	return nil
}

func (x *TestMetadata) GetBugComponent() *BugComponent {
	if x != nil {
		return x.BugComponent
	}
	return nil
}

func (x *TestMetadata) GetPropertiesSchema() string {
	if x != nil {
		return x.PropertiesSchema
	}
	return ""
}

func (x *TestMetadata) GetProperties() *structpb.Struct {
	if x != nil {
		return x.Properties
	}
	return nil
}

// Location of the test definition.
type TestLocation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Gitiles URL as the identifier for a repo.
	// Format for Gitiles URL: https://<host>/<project>
	// For example "https://chromium.googlesource.com/chromium/src"
	// Must not end with ".git".
	// SHOULD be specified.
	Repo string `protobuf:"bytes,1,opt,name=repo,proto3" json:"repo,omitempty"`
	// Name of the file where the test is defined.
	// For files in a repository, must start with "//"
	// Example: "//components/payments/core/payment_request_data_util_unittest.cc"
	// Max length: 512.
	// MUST not use backslashes.
	// Required.
	FileName string `protobuf:"bytes,2,opt,name=file_name,json=fileName,proto3" json:"file_name,omitempty"`
	// One-based line number where the test is defined.
	Line int32 `protobuf:"varint,3,opt,name=line,proto3" json:"line,omitempty"`
}

func (x *TestLocation) Reset() {
	*x = TestLocation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TestLocation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestLocation) ProtoMessage() {}

func (x *TestLocation) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestLocation.ProtoReflect.Descriptor instead.
func (*TestLocation) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{2}
}

func (x *TestLocation) GetRepo() string {
	if x != nil {
		return x.Repo
	}
	return ""
}

func (x *TestLocation) GetFileName() string {
	if x != nil {
		return x.FileName
	}
	return ""
}

func (x *TestLocation) GetLine() int32 {
	if x != nil {
		return x.Line
	}
	return 0
}

// Represents a component in an issue tracker. A component is
// a container for issues.
type BugComponent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to System:
	//
	//	*BugComponent_IssueTracker
	//	*BugComponent_Monorail
	System isBugComponent_System `protobuf_oneof:"system"`
}

func (x *BugComponent) Reset() {
	*x = BugComponent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BugComponent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BugComponent) ProtoMessage() {}

func (x *BugComponent) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BugComponent.ProtoReflect.Descriptor instead.
func (*BugComponent) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{3}
}

func (m *BugComponent) GetSystem() isBugComponent_System {
	if m != nil {
		return m.System
	}
	return nil
}

func (x *BugComponent) GetIssueTracker() *IssueTrackerComponent {
	if x, ok := x.GetSystem().(*BugComponent_IssueTracker); ok {
		return x.IssueTracker
	}
	return nil
}

func (x *BugComponent) GetMonorail() *MonorailComponent {
	if x, ok := x.GetSystem().(*BugComponent_Monorail); ok {
		return x.Monorail
	}
	return nil
}

type isBugComponent_System interface {
	isBugComponent_System()
}

type BugComponent_IssueTracker struct {
	// The Google Issue Tracker component.
	IssueTracker *IssueTrackerComponent `protobuf:"bytes,1,opt,name=issue_tracker,json=issueTracker,proto3,oneof"`
}

type BugComponent_Monorail struct {
	// The monorail component.
	Monorail *MonorailComponent `protobuf:"bytes,2,opt,name=monorail,proto3,oneof"`
}

func (*BugComponent_IssueTracker) isBugComponent_System() {}

func (*BugComponent_Monorail) isBugComponent_System() {}

// A component in Google Issue Tracker, sometimes known as Buganizer,
// available at https://issuetracker.google.com.
type IssueTrackerComponent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Google Issue Tracker component ID.
	ComponentId int64 `protobuf:"varint,1,opt,name=component_id,json=componentId,proto3" json:"component_id,omitempty"`
}

func (x *IssueTrackerComponent) Reset() {
	*x = IssueTrackerComponent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssueTrackerComponent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueTrackerComponent) ProtoMessage() {}

func (x *IssueTrackerComponent) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueTrackerComponent.ProtoReflect.Descriptor instead.
func (*IssueTrackerComponent) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{4}
}

func (x *IssueTrackerComponent) GetComponentId() int64 {
	if x != nil {
		return x.ComponentId
	}
	return 0
}

// A component in monorail issue tracker, available at
// https://bugs.chromium.org.
type MonorailComponent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The monorail project name.
	Project string `protobuf:"bytes,1,opt,name=project,proto3" json:"project,omitempty"`
	// The monorail component value. E.g. "Blink>Accessibility".
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *MonorailComponent) Reset() {
	*x = MonorailComponent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MonorailComponent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MonorailComponent) ProtoMessage() {}

func (x *MonorailComponent) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MonorailComponent.ProtoReflect.Descriptor instead.
func (*MonorailComponent) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP(), []int{5}
}

func (x *MonorailComponent) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *MonorailComponent) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

var File_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto protoreflect.FileDescriptor

var file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDesc = []byte{
	0x0a, 0x3a, 0x67, 0x6f, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x6f, 0x72,
	0x67, 0x2f, 0x6c, 0x75, 0x63, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x6c, 0x75,
	0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1c,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62,
	0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x33, 0x67,
	0x6f, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x6c,
	0x75, 0x63, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xfb, 0x01, 0x0a, 0x12, 0x54, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x17, 0x0a, 0x07,
	0x74, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74,
	0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x65, 0x66, 0x5f, 0x68, 0x61, 0x73,
	0x68, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x65, 0x66, 0x48, 0x61, 0x73, 0x68,
	0x12, 0x3a, 0x0a, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x72, 0x65, 0x66, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x65,
	0x66, 0x52, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x65, 0x66, 0x12, 0x42, 0x0a, 0x0c,
	0x74, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x52, 0x0c, 0x74, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x89, 0x02, 0x0a, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x3a, 0x0a, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x4c,
	0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x43, 0x0a, 0x0d, 0x62, 0x75, 0x67, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65,
	0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x75, 0x67, 0x43,
	0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x52, 0x0c, 0x62, 0x75, 0x67, 0x43, 0x6f, 0x6d,
	0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x12, 0x2b, 0x0a, 0x11, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72,
	0x74, 0x69, 0x65, 0x73, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x10, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x53, 0x63, 0x68,
	0x65, 0x6d, 0x61, 0x12, 0x37, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65,
	0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x52, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x22, 0x53, 0x0a, 0x0c,
	0x54, 0x65, 0x73, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04,
	0x72, 0x65, 0x70, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x65, 0x70, 0x6f,
	0x12, 0x1b, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x6c, 0x69, 0x6e,
	0x65, 0x22, 0xab, 0x01, 0x0a, 0x0c, 0x42, 0x75, 0x67, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65,
	0x6e, 0x74, 0x12, 0x4e, 0x0a, 0x0d, 0x69, 0x73, 0x73, 0x75, 0x65, 0x5f, 0x74, 0x72, 0x61, 0x63,
	0x6b, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x6c, 0x75, 0x63, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x73, 0x73,
	0x75, 0x65, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65,
	0x6e, 0x74, 0x48, 0x00, 0x52, 0x0c, 0x69, 0x73, 0x73, 0x75, 0x65, 0x54, 0x72, 0x61, 0x63, 0x6b,
	0x65, 0x72, 0x12, 0x41, 0x0a, 0x08, 0x6d, 0x6f, 0x6e, 0x6f, 0x72, 0x61, 0x69, 0x6c, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x6f, 0x6e, 0x6f, 0x72, 0x61, 0x69, 0x6c,
	0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x08, 0x6d, 0x6f, 0x6e,
	0x6f, 0x72, 0x61, 0x69, 0x6c, 0x42, 0x08, 0x0a, 0x06, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x22,
	0x3a, 0x0a, 0x15, 0x49, 0x73, 0x73, 0x75, 0x65, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x43,
	0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x70,
	0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b,
	0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x22, 0x43, 0x0a, 0x11, 0x4d,
	0x6f, 0x6e, 0x6f, 0x72, 0x61, 0x69, 0x6c, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x42, 0x31, 0x5a, 0x2f, 0x67, 0x6f, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e,
	0x6f, 0x72, 0x67, 0x2f, 0x6c, 0x75, 0x63, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64,
	0x62, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x3b, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescOnce sync.Once
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescData = file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDesc
)

func file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescGZIP() []byte {
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescOnce.Do(func() {
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescData = protoimpl.X.CompressGZIP(file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescData)
	})
	return file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDescData
}

var file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_goTypes = []interface{}{
	(*TestMetadataDetail)(nil),    // 0: luci.resultdb.v1.TestMetadataDetail
	(*TestMetadata)(nil),          // 1: luci.resultdb.v1.TestMetadata
	(*TestLocation)(nil),          // 2: luci.resultdb.v1.TestLocation
	(*BugComponent)(nil),          // 3: luci.resultdb.v1.BugComponent
	(*IssueTrackerComponent)(nil), // 4: luci.resultdb.v1.IssueTrackerComponent
	(*MonorailComponent)(nil),     // 5: luci.resultdb.v1.MonorailComponent
	(*SourceRef)(nil),             // 6: luci.resultdb.v1.SourceRef
	(*structpb.Struct)(nil),       // 7: google.protobuf.Struct
}
var file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_depIdxs = []int32{
	6, // 0: luci.resultdb.v1.TestMetadataDetail.source_ref:type_name -> luci.resultdb.v1.SourceRef
	1, // 1: luci.resultdb.v1.TestMetadataDetail.testMetadata:type_name -> luci.resultdb.v1.TestMetadata
	2, // 2: luci.resultdb.v1.TestMetadata.location:type_name -> luci.resultdb.v1.TestLocation
	3, // 3: luci.resultdb.v1.TestMetadata.bug_component:type_name -> luci.resultdb.v1.BugComponent
	7, // 4: luci.resultdb.v1.TestMetadata.properties:type_name -> google.protobuf.Struct
	4, // 5: luci.resultdb.v1.BugComponent.issue_tracker:type_name -> luci.resultdb.v1.IssueTrackerComponent
	5, // 6: luci.resultdb.v1.BugComponent.monorail:type_name -> luci.resultdb.v1.MonorailComponent
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_init() }
func file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_init() {
	if File_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto != nil {
		return
	}
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestMetadataDetail); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestMetadata); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TestLocation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BugComponent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssueTrackerComponent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MonorailComponent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*BugComponent_IssueTracker)(nil),
		(*BugComponent_Monorail)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_goTypes,
		DependencyIndexes: file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_depIdxs,
		MessageInfos:      file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_msgTypes,
	}.Build()
	File_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto = out.File
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_rawDesc = nil
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_goTypes = nil
	file_go_chromium_org_luci_resultdb_proto_v1_test_metadata_proto_depIdxs = nil
}
