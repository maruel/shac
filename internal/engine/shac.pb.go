// Copyright 2023 The Shac Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: shac.proto

package engine

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Document is the root message being decoded in a shac.textproto.
type Document struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Minimum shac version that is required to run this check. This enables
	// printing a better error message. It is a semver string.
	MinShacVersion string `protobuf:"bytes,1,opt,name=min_shac_version,json=minShacVersion,proto3" json:"min_shac_version,omitempty"`
	// When set to true, it is allowed to have checks that access the network.
	AllowNetwork bool `protobuf:"varint,2,opt,name=allow_network,json=allowNetwork,proto3" json:"allow_network,omitempty"`
	// Full list of all loaded package dependencies.
	Requirements *Requirements `protobuf:"bytes,3,opt,name=requirements,proto3" json:"requirements,omitempty"`
	// Digests of all direct and indirect dependencies to confirm the code was not
	// modified.
	Sum *Sum `protobuf:"bytes,4,opt,name=sum,proto3" json:"sum,omitempty"`
	// When set, refers to a local copy to use.
	VendorPath string `protobuf:"bytes,5,opt,name=vendor_path,json=vendorPath,proto3" json:"vendor_path,omitempty"`
	// File paths to ignore/un-ignore. Syntax matches that of .gitignore. See
	// https://git-scm.com/docs/gitignore.
	Ignore []string `protobuf:"bytes,6,rep,name=ignore,proto3" json:"ignore,omitempty"`
}

func (x *Document) Reset() {
	*x = Document{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Document) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Document) ProtoMessage() {}

func (x *Document) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Document.ProtoReflect.Descriptor instead.
func (*Document) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{0}
}

func (x *Document) GetMinShacVersion() string {
	if x != nil {
		return x.MinShacVersion
	}
	return ""
}

func (x *Document) GetAllowNetwork() bool {
	if x != nil {
		return x.AllowNetwork
	}
	return false
}

func (x *Document) GetRequirements() *Requirements {
	if x != nil {
		return x.Requirements
	}
	return nil
}

func (x *Document) GetSum() *Sum {
	if x != nil {
		return x.Sum
	}
	return nil
}

func (x *Document) GetVendorPath() string {
	if x != nil {
		return x.VendorPath
	}
	return ""
}

func (x *Document) GetIgnore() []string {
	if x != nil {
		return x.Ignore
	}
	return nil
}

// Requirements lists all the external dependencies, both direct and transitive
// (indirect).
type Requirements struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// direct are packages referenced by the starlark code via a load() statement.
	Direct []*Dependency `protobuf:"bytes,1,rep,name=direct,proto3" json:"direct,omitempty"`
	// indirect are packages referenced by direct dependencies or transitively.
	Indirect []*Dependency `protobuf:"bytes,2,rep,name=indirect,proto3" json:"indirect,omitempty"`
}

func (x *Requirements) Reset() {
	*x = Requirements{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Requirements) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Requirements) ProtoMessage() {}

func (x *Requirements) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Requirements.ProtoReflect.Descriptor instead.
func (*Requirements) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{1}
}

func (x *Requirements) GetDirect() []*Dependency {
	if x != nil {
		return x.Direct
	}
	return nil
}

func (x *Requirements) GetIndirect() []*Dependency {
	if x != nil {
		return x.Indirect
	}
	return nil
}

// Dependency is a starlark package containing a api.star file that will be
// loaded and become available through a load("@...") statement.
type Dependency struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// url is the URL to the resource without the schema, e.g.
	// "github.com/shac/generic-checks".
	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	// alias is an optional shorthand alias. This is how this is referenced to in
	// load() statements.
	Alias string `protobuf:"bytes,2,opt,name=alias,proto3" json:"alias,omitempty"`
	// version is the pinned version to use the dependency.
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *Dependency) Reset() {
	*x = Dependency{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Dependency) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dependency) ProtoMessage() {}

func (x *Dependency) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dependency.ProtoReflect.Descriptor instead.
func (*Dependency) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{2}
}

func (x *Dependency) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *Dependency) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *Dependency) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

// Sum is the digest of known dependencies.
type Sum struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Known []*Known `protobuf:"bytes,1,rep,name=known,proto3" json:"known,omitempty"`
}

func (x *Sum) Reset() {
	*x = Sum{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Sum) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sum) ProtoMessage() {}

func (x *Sum) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sum.ProtoReflect.Descriptor instead.
func (*Sum) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{3}
}

func (x *Sum) GetKnown() []*Known {
	if x != nil {
		return x.Known
	}
	return nil
}

// Known is the multiple known digests of a single dependency.
type Known struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Url  string           `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	Seen []*VersionDigest `protobuf:"bytes,2,rep,name=seen,proto3" json:"seen,omitempty"`
}

func (x *Known) Reset() {
	*x = Known{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Known) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Known) ProtoMessage() {}

func (x *Known) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Known.ProtoReflect.Descriptor instead.
func (*Known) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{4}
}

func (x *Known) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *Known) GetSeen() []*VersionDigest {
	if x != nil {
		return x.Seen
	}
	return nil
}

// VersionDigest is a version:digest pair.
type VersionDigest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// version is one of the version referred to directly or transitively.
	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	// digest is the hash of the content of the dependency. It uses the same
	// hashing algorithm than go.sum. See https://golang.org/x/mod/sumdb/dirhash.
	Digest string `protobuf:"bytes,2,opt,name=digest,proto3" json:"digest,omitempty"`
}

func (x *VersionDigest) Reset() {
	*x = VersionDigest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shac_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VersionDigest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VersionDigest) ProtoMessage() {}

func (x *VersionDigest) ProtoReflect() protoreflect.Message {
	mi := &file_shac_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VersionDigest.ProtoReflect.Descriptor instead.
func (*VersionDigest) Descriptor() ([]byte, []int) {
	return file_shac_proto_rawDescGZIP(), []int{5}
}

func (x *VersionDigest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *VersionDigest) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

var File_shac_proto protoreflect.FileDescriptor

var file_shac_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x73, 0x68, 0x61, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x65, 0x6e,
	0x67, 0x69, 0x6e, 0x65, 0x22, 0xeb, 0x01, 0x0a, 0x08, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e,
	0x74, 0x12, 0x28, 0x0a, 0x10, 0x6d, 0x69, 0x6e, 0x5f, 0x73, 0x68, 0x61, 0x63, 0x5f, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6d, 0x69, 0x6e,
	0x53, 0x68, 0x61, 0x63, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x61,
	0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0c, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x12, 0x38, 0x0a, 0x0c, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e,
	0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x0c, 0x72, 0x65,
	0x71, 0x75, 0x69, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x1d, 0x0a, 0x03, 0x73, 0x75,
	0x6d, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65,
	0x2e, 0x53, 0x75, 0x6d, 0x52, 0x03, 0x73, 0x75, 0x6d, 0x12, 0x1f, 0x0a, 0x0b, 0x76, 0x65, 0x6e,
	0x64, 0x6f, 0x72, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x50, 0x61, 0x74, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x67,
	0x6e, 0x6f, 0x72, 0x65, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x69, 0x67, 0x6e, 0x6f,
	0x72, 0x65, 0x22, 0x6a, 0x0a, 0x0c, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x6d, 0x65, 0x6e,
	0x74, 0x73, 0x12, 0x2a, 0x0a, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x12, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x44, 0x65, 0x70, 0x65,
	0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x52, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x12, 0x2e,
	0x0a, 0x08, 0x69, 0x6e, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x12, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64,
	0x65, 0x6e, 0x63, 0x79, 0x52, 0x08, 0x69, 0x6e, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x22, 0x4e,
	0x0a, 0x0a, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x12, 0x14,
	0x0a, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x61,
	0x6c, 0x69, 0x61, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x2a,
	0x0a, 0x03, 0x53, 0x75, 0x6d, 0x12, 0x23, 0x0a, 0x05, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x4b, 0x6e,
	0x6f, 0x77, 0x6e, 0x52, 0x05, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x22, 0x44, 0x0a, 0x05, 0x4b, 0x6e,
	0x6f, 0x77, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x75, 0x72, 0x6c, 0x12, 0x29, 0x0a, 0x04, 0x73, 0x65, 0x65, 0x6e, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x2e, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x52, 0x04, 0x73, 0x65, 0x65, 0x6e,
	0x22, 0x41, 0x0a, 0x0d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x69, 0x67, 0x65, 0x73,
	0x74, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x64,
	0x69, 0x67, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x69, 0x67,
	0x65, 0x73, 0x74, 0x42, 0x32, 0x5a, 0x30, 0x67, 0x6f, 0x2e, 0x66, 0x75, 0x63, 0x68, 0x73, 0x69,
	0x61, 0x2e, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x61, 0x63, 0x2d, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x2f, 0x73, 0x68, 0x61, 0x63, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
	0x2f, 0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_shac_proto_rawDescOnce sync.Once
	file_shac_proto_rawDescData = file_shac_proto_rawDesc
)

func file_shac_proto_rawDescGZIP() []byte {
	file_shac_proto_rawDescOnce.Do(func() {
		file_shac_proto_rawDescData = protoimpl.X.CompressGZIP(file_shac_proto_rawDescData)
	})
	return file_shac_proto_rawDescData
}

var file_shac_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_shac_proto_goTypes = []interface{}{
	(*Document)(nil),      // 0: engine.Document
	(*Requirements)(nil),  // 1: engine.Requirements
	(*Dependency)(nil),    // 2: engine.Dependency
	(*Sum)(nil),           // 3: engine.Sum
	(*Known)(nil),         // 4: engine.Known
	(*VersionDigest)(nil), // 5: engine.VersionDigest
}
var file_shac_proto_depIdxs = []int32{
	1, // 0: engine.Document.requirements:type_name -> engine.Requirements
	3, // 1: engine.Document.sum:type_name -> engine.Sum
	2, // 2: engine.Requirements.direct:type_name -> engine.Dependency
	2, // 3: engine.Requirements.indirect:type_name -> engine.Dependency
	4, // 4: engine.Sum.known:type_name -> engine.Known
	5, // 5: engine.Known.seen:type_name -> engine.VersionDigest
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_shac_proto_init() }
func file_shac_proto_init() {
	if File_shac_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_shac_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Document); i {
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
		file_shac_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Requirements); i {
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
		file_shac_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Dependency); i {
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
		file_shac_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Sum); i {
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
		file_shac_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Known); i {
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
		file_shac_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VersionDigest); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_shac_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_shac_proto_goTypes,
		DependencyIndexes: file_shac_proto_depIdxs,
		MessageInfos:      file_shac_proto_msgTypes,
	}.Build()
	File_shac_proto = out.File
	file_shac_proto_rawDesc = nil
	file_shac_proto_goTypes = nil
	file_shac_proto_depIdxs = nil
}
