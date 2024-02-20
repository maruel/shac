// Copyright 2019 The LUCI Authors.
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
// source: go.chromium.org/luci/resultdb/proto/v1/common.proto

package resultpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// A key-value map describing one variant of a test case.
//
// The same test case can be executed in different ways, for example on
// different OS, GPUs, with different compile options or runtime flags.
// A variant definition captures one variant.
// A test case with a specific variant definition is called test variant.
//
// Guidelines for variant definition design:
//   - This rule guides what keys MUST be present in the definition.
//     A single expected result of a given test variant is enough to consider it
//     passing (potentially flakily). If it is important to differentiate across
//     a certain dimension (e.g. whether web tests are executed with or without
//     site per process isolation), then there MUST be a key that captures the
//     dimension (e.g. a name from test_suites.pyl).
//     Otherwise, a pass in one variant will hide a failure of another one.
//
//   - This rule guides what keys MUST NOT be present in the definition.
//     A change in the key-value set essentially resets the test result history.
//     For example, if GN args are among variant key-value pairs, then adding a
//     new GN arg changes the identity of the test variant and resets its history.
//
// In Chromium, variant keys are:
//   - bucket: the LUCI bucket, e.g. "ci"
//   - builder: the LUCI builder, e.g. "linux-rel"
//   - test_suite: a name from
//     https://cs.chromium.org/chromium/src/testing/buildbot/test_suites.pyl
type Variant struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The definition of the variant.
	// Key and values must be valid StringPair keys and values, see their
	// constraints.
	Def map[string]string `protobuf:"bytes,1,rep,name=def,proto3" json:"def,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Variant) Reset() {
	*x = Variant{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Variant) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Variant) ProtoMessage() {}

func (x *Variant) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Variant.ProtoReflect.Descriptor instead.
func (*Variant) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{0}
}

func (x *Variant) GetDef() map[string]string {
	if x != nil {
		return x.Def
	}
	return nil
}

// A string key-value pair. Typically used for tagging, see Invocation.tags
type StringPair struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Regex: ^[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*)*$
	// Max length: 64.
	Key string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// Max length: 256.
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *StringPair) Reset() {
	*x = StringPair{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StringPair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StringPair) ProtoMessage() {}

func (x *StringPair) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StringPair.ProtoReflect.Descriptor instead.
func (*StringPair) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{1}
}

func (x *StringPair) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *StringPair) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

// GitilesCommit specifies the position of the gitiles commit an invocation
// ran against, in a repository's commit log. More specifically, a ref's commit
// log.
//
// It also specifies the host/project/ref combination that the commit
// exists in, to provide context.
type GitilesCommit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The identity of the gitiles host, e.g. "chromium.googlesource.com".
	// Mandatory.
	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	// Repository name on the host, e.g. "chromium/src". Mandatory.
	Project string `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`
	// Commit ref, e.g. "refs/heads/main" from which the commit was fetched.
	// Not the branch name, use "refs/heads/branch"
	// Mandatory.
	Ref string `protobuf:"bytes,3,opt,name=ref,proto3" json:"ref,omitempty"`
	// Commit HEX SHA1. All lowercase. Mandatory.
	CommitHash string `protobuf:"bytes,4,opt,name=commit_hash,json=commitHash,proto3" json:"commit_hash,omitempty"`
	// Defines a total order of commits on the ref.
	// A positive, monotonically increasing integer. The recommended
	// way of obtaining this is by using the goto.google.com/git-numberer
	// Gerrit plugin. Other solutions can be used as well, so long
	// as the same scheme is used consistently for a ref.
	// Mandatory.
	Position int64 `protobuf:"varint,5,opt,name=position,proto3" json:"position,omitempty"`
}

func (x *GitilesCommit) Reset() {
	*x = GitilesCommit{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GitilesCommit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GitilesCommit) ProtoMessage() {}

func (x *GitilesCommit) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GitilesCommit.ProtoReflect.Descriptor instead.
func (*GitilesCommit) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{2}
}

func (x *GitilesCommit) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *GitilesCommit) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *GitilesCommit) GetRef() string {
	if x != nil {
		return x.Ref
	}
	return ""
}

func (x *GitilesCommit) GetCommitHash() string {
	if x != nil {
		return x.CommitHash
	}
	return ""
}

func (x *GitilesCommit) GetPosition() int64 {
	if x != nil {
		return x.Position
	}
	return 0
}

// A Gerrit patchset.
type GerritChange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Gerrit hostname, e.g. "chromium-review.googlesource.com".
	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	// Gerrit project, e.g. "chromium/src".
	Project string `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`
	// Change number, e.g. 12345.
	Change int64 `protobuf:"varint,3,opt,name=change,proto3" json:"change,omitempty"`
	// Patch set number, e.g. 1.
	Patchset int64 `protobuf:"varint,4,opt,name=patchset,proto3" json:"patchset,omitempty"`
}

func (x *GerritChange) Reset() {
	*x = GerritChange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GerritChange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GerritChange) ProtoMessage() {}

func (x *GerritChange) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GerritChange.ProtoReflect.Descriptor instead.
func (*GerritChange) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{3}
}

func (x *GerritChange) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *GerritChange) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *GerritChange) GetChange() int64 {
	if x != nil {
		return x.Change
	}
	return 0
}

func (x *GerritChange) GetPatchset() int64 {
	if x != nil {
		return x.Patchset
	}
	return 0
}

// Deprecated: Use GitilesCommit instead.
type CommitPosition struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The following fields identify a git repository and a ref within which the
	// numerical position below identifies a single commit.
	Host    string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Project string `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`
	Ref     string `protobuf:"bytes,3,opt,name=ref,proto3" json:"ref,omitempty"`
	// The numerical position of the commit in the log for the host/project/ref
	// above.
	Position int64 `protobuf:"varint,4,opt,name=position,proto3" json:"position,omitempty"`
}

func (x *CommitPosition) Reset() {
	*x = CommitPosition{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommitPosition) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommitPosition) ProtoMessage() {}

func (x *CommitPosition) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommitPosition.ProtoReflect.Descriptor instead.
func (*CommitPosition) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{4}
}

func (x *CommitPosition) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *CommitPosition) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *CommitPosition) GetRef() string {
	if x != nil {
		return x.Ref
	}
	return ""
}

func (x *CommitPosition) GetPosition() int64 {
	if x != nil {
		return x.Position
	}
	return 0
}

// Deprecated: Do not use.
type CommitPositionRange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The lowest commit position to include in the range.
	Earliest *CommitPosition `protobuf:"bytes,1,opt,name=earliest,proto3" json:"earliest,omitempty"`
	// Include only commit positions that that are strictly lower than this.
	Latest *CommitPosition `protobuf:"bytes,2,opt,name=latest,proto3" json:"latest,omitempty"`
}

func (x *CommitPositionRange) Reset() {
	*x = CommitPositionRange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommitPositionRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommitPositionRange) ProtoMessage() {}

func (x *CommitPositionRange) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommitPositionRange.ProtoReflect.Descriptor instead.
func (*CommitPositionRange) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{5}
}

func (x *CommitPositionRange) GetEarliest() *CommitPosition {
	if x != nil {
		return x.Earliest
	}
	return nil
}

func (x *CommitPositionRange) GetLatest() *CommitPosition {
	if x != nil {
		return x.Latest
	}
	return nil
}

// A range of timestamps.
//
// Currently unused.
type TimeRange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The oldest timestamp to include in the range.
	Earliest *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=earliest,proto3" json:"earliest,omitempty"`
	// Include only timestamps that are strictly older than this.
	Latest *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=latest,proto3" json:"latest,omitempty"`
}

func (x *TimeRange) Reset() {
	*x = TimeRange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TimeRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TimeRange) ProtoMessage() {}

func (x *TimeRange) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TimeRange.ProtoReflect.Descriptor instead.
func (*TimeRange) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{6}
}

func (x *TimeRange) GetEarliest() *timestamppb.Timestamp {
	if x != nil {
		return x.Earliest
	}
	return nil
}

func (x *TimeRange) GetLatest() *timestamppb.Timestamp {
	if x != nil {
		return x.Latest
	}
	return nil
}

// Represents a reference in a source control system.
type SourceRef struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The source control system used.
	// Only gitiles is supported at this moment. If other systems need to be
	// supported in future (e.g. non-gitiles git, subversion, google storage
	// buckets), they can be added here
	//
	// Types that are assignable to System:
	//
	//	*SourceRef_Gitiles
	System isSourceRef_System `protobuf_oneof:"system"`
}

func (x *SourceRef) Reset() {
	*x = SourceRef{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SourceRef) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SourceRef) ProtoMessage() {}

func (x *SourceRef) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SourceRef.ProtoReflect.Descriptor instead.
func (*SourceRef) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{7}
}

func (m *SourceRef) GetSystem() isSourceRef_System {
	if m != nil {
		return m.System
	}
	return nil
}

func (x *SourceRef) GetGitiles() *GitilesRef {
	if x, ok := x.GetSystem().(*SourceRef_Gitiles); ok {
		return x.Gitiles
	}
	return nil
}

type isSourceRef_System interface {
	isSourceRef_System()
}

type SourceRef_Gitiles struct {
	// A branch in gitiles repository.
	Gitiles *GitilesRef `protobuf:"bytes,1,opt,name=gitiles,proto3,oneof"`
}

func (*SourceRef_Gitiles) isSourceRef_System() {}

// Represents a branch in a gitiles repository.
type GitilesRef struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The gitiles host, e.g. "chromium.googlesource.com".
	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	// The project on the gitiles host, e.g. "chromium/src".
	Project string `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`
	// Commit ref, e.g. "refs/heads/main" from which the commit was fetched.
	// Not the branch name, use "refs/heads/branch"
	Ref string `protobuf:"bytes,3,opt,name=ref,proto3" json:"ref,omitempty"`
}

func (x *GitilesRef) Reset() {
	*x = GitilesRef{}
	if protoimpl.UnsafeEnabled {
		mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GitilesRef) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GitilesRef) ProtoMessage() {}

func (x *GitilesRef) ProtoReflect() protoreflect.Message {
	mi := &file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GitilesRef.ProtoReflect.Descriptor instead.
func (*GitilesRef) Descriptor() ([]byte, []int) {
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP(), []int{8}
}

func (x *GitilesRef) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *GitilesRef) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *GitilesRef) GetRef() string {
	if x != nil {
		return x.Ref
	}
	return ""
}

var File_go_chromium_org_luci_resultdb_proto_v1_common_proto protoreflect.FileDescriptor

var file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDesc = []byte{
	0x0a, 0x33, 0x67, 0x6f, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x6f, 0x72,
	0x67, 0x2f, 0x6c, 0x75, 0x63, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x77, 0x0a, 0x07, 0x56, 0x61, 0x72, 0x69,
	0x61, 0x6e, 0x74, 0x12, 0x34, 0x0a, 0x03, 0x64, 0x65, 0x66, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x22, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62,
	0x2e, 0x76, 0x31, 0x2e, 0x56, 0x61, 0x72, 0x69, 0x61, 0x6e, 0x74, 0x2e, 0x44, 0x65, 0x66, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x03, 0x64, 0x65, 0x66, 0x1a, 0x36, 0x0a, 0x08, 0x44, 0x65, 0x66,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x34, 0x0a, 0x0a, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x50, 0x61, 0x69, 0x72, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x8c, 0x01, 0x0a, 0x0d, 0x47, 0x69, 0x74, 0x69,
	0x6c, 0x65, 0x73, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x65, 0x66, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x72, 0x65, 0x66, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x48, 0x61, 0x73, 0x68, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x6f,
	0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x70, 0x6f,
	0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x70, 0x0a, 0x0c, 0x47, 0x65, 0x72, 0x72, 0x69, 0x74,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72,
	0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x1a, 0x0a, 0x08,
	0x70, 0x61, 0x74, 0x63, 0x68, 0x73, 0x65, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08,
	0x70, 0x61, 0x74, 0x63, 0x68, 0x73, 0x65, 0x74, 0x22, 0x6c, 0x0a, 0x0e, 0x43, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x18,
	0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x65, 0x66, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x72, 0x65, 0x66, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x6f,
	0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x70, 0x6f,
	0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x8d, 0x01, 0x0a, 0x13, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x3c,
	0x0a, 0x08, 0x65, 0x61, 0x72, 0x6c, 0x69, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x20, 0x2e, 0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x08, 0x65, 0x61, 0x72, 0x6c, 0x69, 0x65, 0x73, 0x74, 0x12, 0x38, 0x0a, 0x06,
	0x6c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6c,
	0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x50, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x06,
	0x6c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x22, 0x77, 0x0a, 0x09, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x61,
	0x6e, 0x67, 0x65, 0x12, 0x36, 0x0a, 0x08, 0x65, 0x61, 0x72, 0x6c, 0x69, 0x65, 0x73, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x08, 0x65, 0x61, 0x72, 0x6c, 0x69, 0x65, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x06, 0x6c,
	0x61, 0x74, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x06, 0x6c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x22,
	0x4f, 0x0a, 0x09, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x65, 0x66, 0x12, 0x38, 0x0a, 0x07,
	0x67, 0x69, 0x74, 0x69, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x6c, 0x75, 0x63, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x69, 0x74, 0x69, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x66, 0x48, 0x00, 0x52, 0x07, 0x67,
	0x69, 0x74, 0x69, 0x6c, 0x65, 0x73, 0x42, 0x08, 0x0a, 0x06, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x22, 0x4c, 0x0a, 0x0a, 0x47, 0x69, 0x74, 0x69, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x66, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x10, 0x0a, 0x03,
	0x72, 0x65, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x72, 0x65, 0x66, 0x42, 0x31,
	0x5a, 0x2f, 0x67, 0x6f, 0x2e, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x69, 0x75, 0x6d, 0x2e, 0x6f, 0x72,
	0x67, 0x2f, 0x6c, 0x75, 0x63, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x64, 0x62, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x3b, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x70,
	0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescOnce sync.Once
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescData = file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDesc
)

func file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescGZIP() []byte {
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescOnce.Do(func() {
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescData = protoimpl.X.CompressGZIP(file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescData)
	})
	return file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDescData
}

var file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_go_chromium_org_luci_resultdb_proto_v1_common_proto_goTypes = []interface{}{
	(*Variant)(nil),               // 0: luci.resultdb.v1.Variant
	(*StringPair)(nil),            // 1: luci.resultdb.v1.StringPair
	(*GitilesCommit)(nil),         // 2: luci.resultdb.v1.GitilesCommit
	(*GerritChange)(nil),          // 3: luci.resultdb.v1.GerritChange
	(*CommitPosition)(nil),        // 4: luci.resultdb.v1.CommitPosition
	(*CommitPositionRange)(nil),   // 5: luci.resultdb.v1.CommitPositionRange
	(*TimeRange)(nil),             // 6: luci.resultdb.v1.TimeRange
	(*SourceRef)(nil),             // 7: luci.resultdb.v1.SourceRef
	(*GitilesRef)(nil),            // 8: luci.resultdb.v1.GitilesRef
	nil,                           // 9: luci.resultdb.v1.Variant.DefEntry
	(*timestamppb.Timestamp)(nil), // 10: google.protobuf.Timestamp
}
var file_go_chromium_org_luci_resultdb_proto_v1_common_proto_depIdxs = []int32{
	9,  // 0: luci.resultdb.v1.Variant.def:type_name -> luci.resultdb.v1.Variant.DefEntry
	4,  // 1: luci.resultdb.v1.CommitPositionRange.earliest:type_name -> luci.resultdb.v1.CommitPosition
	4,  // 2: luci.resultdb.v1.CommitPositionRange.latest:type_name -> luci.resultdb.v1.CommitPosition
	10, // 3: luci.resultdb.v1.TimeRange.earliest:type_name -> google.protobuf.Timestamp
	10, // 4: luci.resultdb.v1.TimeRange.latest:type_name -> google.protobuf.Timestamp
	8,  // 5: luci.resultdb.v1.SourceRef.gitiles:type_name -> luci.resultdb.v1.GitilesRef
	6,  // [6:6] is the sub-list for method output_type
	6,  // [6:6] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_go_chromium_org_luci_resultdb_proto_v1_common_proto_init() }
func file_go_chromium_org_luci_resultdb_proto_v1_common_proto_init() {
	if File_go_chromium_org_luci_resultdb_proto_v1_common_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Variant); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StringPair); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GitilesCommit); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GerritChange); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommitPosition); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommitPositionRange); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TimeRange); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SourceRef); i {
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
		file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GitilesRef); i {
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
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*SourceRef_Gitiles)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_go_chromium_org_luci_resultdb_proto_v1_common_proto_goTypes,
		DependencyIndexes: file_go_chromium_org_luci_resultdb_proto_v1_common_proto_depIdxs,
		MessageInfos:      file_go_chromium_org_luci_resultdb_proto_v1_common_proto_msgTypes,
	}.Build()
	File_go_chromium_org_luci_resultdb_proto_v1_common_proto = out.File
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_rawDesc = nil
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_goTypes = nil
	file_go_chromium_org_luci_resultdb_proto_v1_common_proto_depIdxs = nil
}
