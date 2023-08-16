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
// source: sarif.proto

// Package sarif contains types that conform to the SARIF static analysis spec:
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html.
//
// Serialization must be done with `performing_proto_field_names = false` as the
// SARIF spec requires camelCase field names.

package sarif

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

// Document is the type of the top-level JSON object in SARIF output.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540916
type Document struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Runs    []*Run `protobuf:"bytes,2,rep,name=runs,proto3" json:"runs,omitempty"`
}

func (x *Document) Reset() {
	*x = Document{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Document) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Document) ProtoMessage() {}

func (x *Document) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[0]
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
	return file_sarif_proto_rawDescGZIP(), []int{0}
}

func (x *Document) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Document) GetRuns() []*Run {
	if x != nil {
		return x.Runs
	}
	return nil
}

// Run describes a single run of an analysis tool and contains the output of
// that run.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540922
type Run struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tool    *Tool     `protobuf:"bytes,1,opt,name=tool,proto3" json:"tool,omitempty"`
	Results []*Result `protobuf:"bytes,2,rep,name=results,proto3" json:"results,omitempty"`
}

func (x *Run) Reset() {
	*x = Run{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Run) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Run) ProtoMessage() {}

func (x *Run) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Run.ProtoReflect.Descriptor instead.
func (*Run) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{1}
}

func (x *Run) GetTool() *Tool {
	if x != nil {
		return x.Tool
	}
	return nil
}

func (x *Run) GetResults() []*Result {
	if x != nil {
		return x.Results
	}
	return nil
}

// Tool describes the analysis tool that was run.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540967
type Tool struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Driver     *ToolComponent   `protobuf:"bytes,1,opt,name=driver,proto3" json:"driver,omitempty"`
	Extensions []*ToolComponent `protobuf:"bytes,2,rep,name=extensions,proto3" json:"extensions,omitempty"`
}

func (x *Tool) Reset() {
	*x = Tool{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tool) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tool) ProtoMessage() {}

func (x *Tool) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tool.ProtoReflect.Descriptor instead.
func (*Tool) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{2}
}

func (x *Tool) GetDriver() *ToolComponent {
	if x != nil {
		return x.Driver
	}
	return nil
}

func (x *Tool) GetExtensions() []*ToolComponent {
	if x != nil {
		return x.Extensions
	}
	return nil
}

// ToolComponent represents a tool driver or extension.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540971
type ToolComponent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the name of the tool component. Required.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *ToolComponent) Reset() {
	*x = ToolComponent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ToolComponent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ToolComponent) ProtoMessage() {}

func (x *ToolComponent) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ToolComponent.ProtoReflect.Descriptor instead.
func (*ToolComponent) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{3}
}

func (x *ToolComponent) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// Result describes a single result detected by an analysis tool.
//
// The "kind" field is optional and defaults to "fail".
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541076
type Result struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// "note", "warning", or "error".
	Level   string   `protobuf:"bytes,1,opt,name=level,proto3" json:"level,omitempty"`
	Message *Message `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	// The code locations that the result applies to.
	Locations []*Location `protobuf:"bytes,3,rep,name=locations,proto3" json:"locations,omitempty"`
	Fixes     []*Fix      `protobuf:"bytes,4,rep,name=fixes,proto3" json:"fixes,omitempty"`
}

func (x *Result) Reset() {
	*x = Result{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Result) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Result) ProtoMessage() {}

func (x *Result) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Result.ProtoReflect.Descriptor instead.
func (*Result) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{4}
}

func (x *Result) GetLevel() string {
	if x != nil {
		return x.Level
	}
	return ""
}

func (x *Result) GetMessage() *Message {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *Result) GetLocations() []*Location {
	if x != nil {
		return x.Locations
	}
	return nil
}

func (x *Result) GetFixes() []*Fix {
	if x != nil {
		return x.Fixes
	}
	return nil
}

// Message is a user-facing message for the result.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540897
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Text string `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{5}
}

func (x *Message) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541108
type Location struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PhysicalLocation *PhysicalLocation `protobuf:"bytes,1,opt,name=physical_location,json=physicalLocation,proto3" json:"physical_location,omitempty"`
}

func (x *Location) Reset() {
	*x = Location{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Location) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Location) ProtoMessage() {}

func (x *Location) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Location.ProtoReflect.Descriptor instead.
func (*Location) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{6}
}

func (x *Location) GetPhysicalLocation() *PhysicalLocation {
	if x != nil {
		return x.PhysicalLocation
	}
	return nil
}

// PhysicalLocation references the location where a result was detected.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541116
type PhysicalLocation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ArtifactLocation *ArtifactLocation `protobuf:"bytes,1,opt,name=artifact_location,json=artifactLocation,proto3" json:"artifact_location,omitempty"`
	Region           *Region           `protobuf:"bytes,2,opt,name=region,proto3" json:"region,omitempty"`
}

func (x *PhysicalLocation) Reset() {
	*x = PhysicalLocation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PhysicalLocation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PhysicalLocation) ProtoMessage() {}

func (x *PhysicalLocation) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PhysicalLocation.ProtoReflect.Descriptor instead.
func (*PhysicalLocation) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{7}
}

func (x *PhysicalLocation) GetArtifactLocation() *ArtifactLocation {
	if x != nil {
		return x.ArtifactLocation
	}
	return nil
}

func (x *PhysicalLocation) GetRegion() *Region {
	if x != nil {
		return x.Region
	}
	return nil
}

// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541319
type Fix struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Description     *Message          `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	ArtifactChanges []*ArtifactChange `protobuf:"bytes,2,rep,name=artifact_changes,json=artifactChanges,proto3" json:"artifact_changes,omitempty"`
}

func (x *Fix) Reset() {
	*x = Fix{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Fix) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Fix) ProtoMessage() {}

func (x *Fix) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Fix.ProtoReflect.Descriptor instead.
func (*Fix) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{8}
}

func (x *Fix) GetDescription() *Message {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Fix) GetArtifactChanges() []*ArtifactChange {
	if x != nil {
		return x.ArtifactChanges
	}
	return nil
}

// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541323
type ArtifactChange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ArtifactLocation *ArtifactLocation `protobuf:"bytes,1,opt,name=artifact_location,json=artifactLocation,proto3" json:"artifact_location,omitempty"`
	Replacements     []*Replacement    `protobuf:"bytes,2,rep,name=replacements,proto3" json:"replacements,omitempty"`
}

func (x *ArtifactChange) Reset() {
	*x = ArtifactChange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ArtifactChange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ArtifactChange) ProtoMessage() {}

func (x *ArtifactChange) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ArtifactChange.ProtoReflect.Descriptor instead.
func (*ArtifactChange) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{9}
}

func (x *ArtifactChange) GetArtifactLocation() *ArtifactLocation {
	if x != nil {
		return x.ArtifactLocation
	}
	return nil
}

func (x *ArtifactChange) GetReplacements() []*Replacement {
	if x != nil {
		return x.Replacements
	}
	return nil
}

// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540865
type ArtifactLocation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// URI is the relative path to the referenced file, e.g. "foo/bar/baz.c".
	Uri string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
}

func (x *ArtifactLocation) Reset() {
	*x = ArtifactLocation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ArtifactLocation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ArtifactLocation) ProtoMessage() {}

func (x *ArtifactLocation) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ArtifactLocation.ProtoReflect.Descriptor instead.
func (*ArtifactLocation) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{10}
}

func (x *ArtifactLocation) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

// Replacement indicates the replacement of a region of a file.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541327
type Replacement struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeletedRegion   *Region          `protobuf:"bytes,1,opt,name=deleted_region,json=deletedRegion,proto3" json:"deleted_region,omitempty"`
	InsertedContent *ArtifactContent `protobuf:"bytes,2,opt,name=inserted_content,json=insertedContent,proto3" json:"inserted_content,omitempty"`
}

func (x *Replacement) Reset() {
	*x = Replacement{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Replacement) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Replacement) ProtoMessage() {}

func (x *Replacement) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Replacement.ProtoReflect.Descriptor instead.
func (*Replacement) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{11}
}

func (x *Replacement) GetDeletedRegion() *Region {
	if x != nil {
		return x.DeletedRegion
	}
	return nil
}

func (x *Replacement) GetInsertedContent() *ArtifactContent {
	if x != nil {
		return x.InsertedContent
	}
	return nil
}

// Region represents a continuous segment of a file.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10541123
type Region struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 1-based.
	StartLine int32 `protobuf:"varint,1,opt,name=start_line,json=startLine,proto3" json:"start_line,omitempty"`
	// 1-based.
	StartColumn int32 `protobuf:"varint,2,opt,name=start_column,json=startColumn,proto3" json:"start_column,omitempty"`
	// 1-based, inclusive.
	EndLine int32 `protobuf:"varint,3,opt,name=end_line,json=endLine,proto3" json:"end_line,omitempty"`
	// 1-based, exclusive.
	EndColumn int32 `protobuf:"varint,4,opt,name=end_column,json=endColumn,proto3" json:"end_column,omitempty"`
}

func (x *Region) Reset() {
	*x = Region{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Region) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Region) ProtoMessage() {}

func (x *Region) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Region.ProtoReflect.Descriptor instead.
func (*Region) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{12}
}

func (x *Region) GetStartLine() int32 {
	if x != nil {
		return x.StartLine
	}
	return 0
}

func (x *Region) GetStartColumn() int32 {
	if x != nil {
		return x.StartColumn
	}
	return 0
}

func (x *Region) GetEndLine() int32 {
	if x != nil {
		return x.EndLine
	}
	return 0
}

func (x *Region) GetEndColumn() int32 {
	if x != nil {
		return x.EndColumn
	}
	return 0
}

// ArtifactContent represents contents of a file to insert or replace.
//
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540860
type ArtifactContent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Text string `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`
}

func (x *ArtifactContent) Reset() {
	*x = ArtifactContent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sarif_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ArtifactContent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ArtifactContent) ProtoMessage() {}

func (x *ArtifactContent) ProtoReflect() protoreflect.Message {
	mi := &file_sarif_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ArtifactContent.ProtoReflect.Descriptor instead.
func (*ArtifactContent) Descriptor() ([]byte, []int) {
	return file_sarif_proto_rawDescGZIP(), []int{13}
}

func (x *ArtifactContent) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

var File_sarif_proto protoreflect.FileDescriptor

var file_sarif_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x73,
	0x61, 0x72, 0x69, 0x66, 0x22, 0x44, 0x0a, 0x08, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x04, 0x72, 0x75,
	0x6e, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66,
	0x2e, 0x52, 0x75, 0x6e, 0x52, 0x04, 0x72, 0x75, 0x6e, 0x73, 0x22, 0x4f, 0x0a, 0x03, 0x52, 0x75,
	0x6e, 0x12, 0x1f, 0x0a, 0x04, 0x74, 0x6f, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0b, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x54, 0x6f, 0x6f, 0x6c, 0x52, 0x04, 0x74, 0x6f,
	0x6f, 0x6c, 0x12, 0x27, 0x0a, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x52, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x22, 0x6a, 0x0a, 0x04, 0x54,
	0x6f, 0x6f, 0x6c, 0x12, 0x2c, 0x0a, 0x06, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x54, 0x6f, 0x6f, 0x6c,
	0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x52, 0x06, 0x64, 0x72, 0x69, 0x76, 0x65,
	0x72, 0x12, 0x34, 0x0a, 0x0a, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x54, 0x6f,
	0x6f, 0x6c, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x52, 0x0a, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x23, 0x0a, 0x0d, 0x54, 0x6f, 0x6f, 0x6c, 0x43,
	0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x99, 0x01, 0x0a,
	0x06, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x28, 0x0a,
	0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e,
	0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x07,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2d, 0x0a, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x61, 0x72,
	0x69, 0x66, 0x2e, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x6c, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x20, 0x0a, 0x05, 0x66, 0x69, 0x78, 0x65, 0x73, 0x18,
	0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x46, 0x69,
	0x78, 0x52, 0x05, 0x66, 0x69, 0x78, 0x65, 0x73, 0x22, 0x1d, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x74, 0x65, 0x78, 0x74, 0x22, 0x50, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x44, 0x0a, 0x11, 0x70, 0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6c, 0x5f,
	0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x50, 0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6c, 0x4c,
	0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x10, 0x70, 0x68, 0x79, 0x73, 0x69, 0x63, 0x61,
	0x6c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x7f, 0x0a, 0x10, 0x50, 0x68, 0x79,
	0x73, 0x69, 0x63, 0x61, 0x6c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x44, 0x0a,
	0x11, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66,
	0x2e, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x10, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x25, 0x0a, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x52, 0x65, 0x67, 0x69,
	0x6f, 0x6e, 0x52, 0x06, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x22, 0x79, 0x0a, 0x03, 0x46, 0x69,
	0x78, 0x12, 0x30, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x40, 0x0a, 0x10, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x5f,
	0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e,
	0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x52, 0x0f, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x73, 0x22, 0x8e, 0x01, 0x0a, 0x0e, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61,
	0x63, 0x74, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x44, 0x0a, 0x11, 0x61, 0x72, 0x74, 0x69,
	0x66, 0x61, 0x63, 0x74, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x41, 0x72, 0x74, 0x69,
	0x66, 0x61, 0x63, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x10, 0x61, 0x72,
	0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x36,
	0x0a, 0x0c, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x52, 0x65, 0x70,
	0x6c, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x0c, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
	0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x24, 0x0a, 0x10, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61,
	0x63, 0x74, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72,
	0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x69, 0x22, 0x86, 0x01, 0x0a,
	0x0b, 0x52, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x34, 0x0a, 0x0e,
	0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x61, 0x72, 0x69, 0x66, 0x2e, 0x52, 0x65, 0x67,
	0x69, 0x6f, 0x6e, 0x52, 0x0d, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x52, 0x65, 0x67, 0x69,
	0x6f, 0x6e, 0x12, 0x41, 0x0a, 0x10, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x73,
	0x61, 0x72, 0x69, 0x66, 0x2e, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x52, 0x0f, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x65, 0x64, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x84, 0x01, 0x0a, 0x06, 0x52, 0x65, 0x67, 0x69, 0x6f, 0x6e,
	0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x4c, 0x69, 0x6e, 0x65, 0x12,
	0x21, 0x0a, 0x0c, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x6f, 0x6c, 0x75,
	0x6d, 0x6e, 0x12, 0x19, 0x0a, 0x08, 0x65, 0x6e, 0x64, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x65, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x12, 0x1d, 0x0a,
	0x0a, 0x65, 0x6e, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x09, 0x65, 0x6e, 0x64, 0x43, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x22, 0x25, 0x0a, 0x0f,
	0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74,
	0x65, 0x78, 0x74, 0x42, 0x31, 0x5a, 0x2f, 0x67, 0x6f, 0x2e, 0x66, 0x75, 0x63, 0x68, 0x73, 0x69,
	0x61, 0x2e, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x61, 0x63, 0x2d, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x2f, 0x73, 0x68, 0x61, 0x63, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
	0x2f, 0x73, 0x61, 0x72, 0x69, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_sarif_proto_rawDescOnce sync.Once
	file_sarif_proto_rawDescData = file_sarif_proto_rawDesc
)

func file_sarif_proto_rawDescGZIP() []byte {
	file_sarif_proto_rawDescOnce.Do(func() {
		file_sarif_proto_rawDescData = protoimpl.X.CompressGZIP(file_sarif_proto_rawDescData)
	})
	return file_sarif_proto_rawDescData
}

var file_sarif_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_sarif_proto_goTypes = []interface{}{
	(*Document)(nil),         // 0: sarif.Document
	(*Run)(nil),              // 1: sarif.Run
	(*Tool)(nil),             // 2: sarif.Tool
	(*ToolComponent)(nil),    // 3: sarif.ToolComponent
	(*Result)(nil),           // 4: sarif.Result
	(*Message)(nil),          // 5: sarif.Message
	(*Location)(nil),         // 6: sarif.Location
	(*PhysicalLocation)(nil), // 7: sarif.PhysicalLocation
	(*Fix)(nil),              // 8: sarif.Fix
	(*ArtifactChange)(nil),   // 9: sarif.ArtifactChange
	(*ArtifactLocation)(nil), // 10: sarif.ArtifactLocation
	(*Replacement)(nil),      // 11: sarif.Replacement
	(*Region)(nil),           // 12: sarif.Region
	(*ArtifactContent)(nil),  // 13: sarif.ArtifactContent
}
var file_sarif_proto_depIdxs = []int32{
	1,  // 0: sarif.Document.runs:type_name -> sarif.Run
	2,  // 1: sarif.Run.tool:type_name -> sarif.Tool
	4,  // 2: sarif.Run.results:type_name -> sarif.Result
	3,  // 3: sarif.Tool.driver:type_name -> sarif.ToolComponent
	3,  // 4: sarif.Tool.extensions:type_name -> sarif.ToolComponent
	5,  // 5: sarif.Result.message:type_name -> sarif.Message
	6,  // 6: sarif.Result.locations:type_name -> sarif.Location
	8,  // 7: sarif.Result.fixes:type_name -> sarif.Fix
	7,  // 8: sarif.Location.physical_location:type_name -> sarif.PhysicalLocation
	10, // 9: sarif.PhysicalLocation.artifact_location:type_name -> sarif.ArtifactLocation
	12, // 10: sarif.PhysicalLocation.region:type_name -> sarif.Region
	5,  // 11: sarif.Fix.description:type_name -> sarif.Message
	9,  // 12: sarif.Fix.artifact_changes:type_name -> sarif.ArtifactChange
	10, // 13: sarif.ArtifactChange.artifact_location:type_name -> sarif.ArtifactLocation
	11, // 14: sarif.ArtifactChange.replacements:type_name -> sarif.Replacement
	12, // 15: sarif.Replacement.deleted_region:type_name -> sarif.Region
	13, // 16: sarif.Replacement.inserted_content:type_name -> sarif.ArtifactContent
	17, // [17:17] is the sub-list for method output_type
	17, // [17:17] is the sub-list for method input_type
	17, // [17:17] is the sub-list for extension type_name
	17, // [17:17] is the sub-list for extension extendee
	0,  // [0:17] is the sub-list for field type_name
}

func init() { file_sarif_proto_init() }
func file_sarif_proto_init() {
	if File_sarif_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_sarif_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_sarif_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Run); i {
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
		file_sarif_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tool); i {
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
		file_sarif_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ToolComponent); i {
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
		file_sarif_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Result); i {
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
		file_sarif_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
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
		file_sarif_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Location); i {
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
		file_sarif_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PhysicalLocation); i {
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
		file_sarif_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Fix); i {
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
		file_sarif_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ArtifactChange); i {
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
		file_sarif_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ArtifactLocation); i {
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
		file_sarif_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Replacement); i {
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
		file_sarif_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Region); i {
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
		file_sarif_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ArtifactContent); i {
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
			RawDescriptor: file_sarif_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_sarif_proto_goTypes,
		DependencyIndexes: file_sarif_proto_depIdxs,
		MessageInfos:      file_sarif_proto_msgTypes,
	}.Build()
	File_sarif_proto = out.File
	file_sarif_proto_rawDesc = nil
	file_sarif_proto_goTypes = nil
	file_sarif_proto_depIdxs = nil
}
