// Code generated by MockGen. DO NOT EDIT.
// Source: recorder.pb.go

package resultpb

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	grpc "google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// MockRecorderClient is a mock of RecorderClient interface.
type MockRecorderClient struct {
	ctrl     *gomock.Controller
	recorder *MockRecorderClientMockRecorder
}

// MockRecorderClientMockRecorder is the mock recorder for MockRecorderClient.
type MockRecorderClientMockRecorder struct {
	mock *MockRecorderClient
}

// NewMockRecorderClient creates a new mock instance.
func NewMockRecorderClient(ctrl *gomock.Controller) *MockRecorderClient {
	mock := &MockRecorderClient{ctrl: ctrl}
	mock.recorder = &MockRecorderClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRecorderClient) EXPECT() *MockRecorderClientMockRecorder {
	return m.recorder
}

// BatchCreateArtifacts mocks base method.
func (m *MockRecorderClient) BatchCreateArtifacts(ctx context.Context, in *BatchCreateArtifactsRequest, opts ...grpc.CallOption) (*BatchCreateArtifactsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "BatchCreateArtifacts", varargs...)
	ret0, _ := ret[0].(*BatchCreateArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateArtifacts indicates an expected call of BatchCreateArtifacts.
func (mr *MockRecorderClientMockRecorder) BatchCreateArtifacts(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateArtifacts", reflect.TypeOf((*MockRecorderClient)(nil).BatchCreateArtifacts), varargs...)
}

// BatchCreateInvocations mocks base method.
func (m *MockRecorderClient) BatchCreateInvocations(ctx context.Context, in *BatchCreateInvocationsRequest, opts ...grpc.CallOption) (*BatchCreateInvocationsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "BatchCreateInvocations", varargs...)
	ret0, _ := ret[0].(*BatchCreateInvocationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateInvocations indicates an expected call of BatchCreateInvocations.
func (mr *MockRecorderClientMockRecorder) BatchCreateInvocations(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateInvocations", reflect.TypeOf((*MockRecorderClient)(nil).BatchCreateInvocations), varargs...)
}

// BatchCreateTestExonerations mocks base method.
func (m *MockRecorderClient) BatchCreateTestExonerations(ctx context.Context, in *BatchCreateTestExonerationsRequest, opts ...grpc.CallOption) (*BatchCreateTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "BatchCreateTestExonerations", varargs...)
	ret0, _ := ret[0].(*BatchCreateTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateTestExonerations indicates an expected call of BatchCreateTestExonerations.
func (mr *MockRecorderClientMockRecorder) BatchCreateTestExonerations(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateTestExonerations", reflect.TypeOf((*MockRecorderClient)(nil).BatchCreateTestExonerations), varargs...)
}

// BatchCreateTestResults mocks base method.
func (m *MockRecorderClient) BatchCreateTestResults(ctx context.Context, in *BatchCreateTestResultsRequest, opts ...grpc.CallOption) (*BatchCreateTestResultsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "BatchCreateTestResults", varargs...)
	ret0, _ := ret[0].(*BatchCreateTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateTestResults indicates an expected call of BatchCreateTestResults.
func (mr *MockRecorderClientMockRecorder) BatchCreateTestResults(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateTestResults", reflect.TypeOf((*MockRecorderClient)(nil).BatchCreateTestResults), varargs...)
}

// CreateInvocation mocks base method.
func (m *MockRecorderClient) CreateInvocation(ctx context.Context, in *CreateInvocationRequest, opts ...grpc.CallOption) (*Invocation, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateInvocation", varargs...)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateInvocation indicates an expected call of CreateInvocation.
func (mr *MockRecorderClientMockRecorder) CreateInvocation(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateInvocation", reflect.TypeOf((*MockRecorderClient)(nil).CreateInvocation), varargs...)
}

// CreateTestExoneration mocks base method.
func (m *MockRecorderClient) CreateTestExoneration(ctx context.Context, in *CreateTestExonerationRequest, opts ...grpc.CallOption) (*TestExoneration, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateTestExoneration", varargs...)
	ret0, _ := ret[0].(*TestExoneration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTestExoneration indicates an expected call of CreateTestExoneration.
func (mr *MockRecorderClientMockRecorder) CreateTestExoneration(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTestExoneration", reflect.TypeOf((*MockRecorderClient)(nil).CreateTestExoneration), varargs...)
}

// CreateTestResult mocks base method.
func (m *MockRecorderClient) CreateTestResult(ctx context.Context, in *CreateTestResultRequest, opts ...grpc.CallOption) (*TestResult, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateTestResult", varargs...)
	ret0, _ := ret[0].(*TestResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTestResult indicates an expected call of CreateTestResult.
func (mr *MockRecorderClientMockRecorder) CreateTestResult(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTestResult", reflect.TypeOf((*MockRecorderClient)(nil).CreateTestResult), varargs...)
}

// FinalizeInvocation mocks base method.
func (m *MockRecorderClient) FinalizeInvocation(ctx context.Context, in *FinalizeInvocationRequest, opts ...grpc.CallOption) (*Invocation, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "FinalizeInvocation", varargs...)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FinalizeInvocation indicates an expected call of FinalizeInvocation.
func (mr *MockRecorderClientMockRecorder) FinalizeInvocation(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FinalizeInvocation", reflect.TypeOf((*MockRecorderClient)(nil).FinalizeInvocation), varargs...)
}

// MarkInvocationSubmitted mocks base method.
func (m *MockRecorderClient) MarkInvocationSubmitted(ctx context.Context, in *MarkInvocationSubmittedRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "MarkInvocationSubmitted", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MarkInvocationSubmitted indicates an expected call of MarkInvocationSubmitted.
func (mr *MockRecorderClientMockRecorder) MarkInvocationSubmitted(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MarkInvocationSubmitted", reflect.TypeOf((*MockRecorderClient)(nil).MarkInvocationSubmitted), varargs...)
}

// UpdateIncludedInvocations mocks base method.
func (m *MockRecorderClient) UpdateIncludedInvocations(ctx context.Context, in *UpdateIncludedInvocationsRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateIncludedInvocations", varargs...)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIncludedInvocations indicates an expected call of UpdateIncludedInvocations.
func (mr *MockRecorderClientMockRecorder) UpdateIncludedInvocations(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIncludedInvocations", reflect.TypeOf((*MockRecorderClient)(nil).UpdateIncludedInvocations), varargs...)
}

// UpdateInvocation mocks base method.
func (m *MockRecorderClient) UpdateInvocation(ctx context.Context, in *UpdateInvocationRequest, opts ...grpc.CallOption) (*Invocation, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateInvocation", varargs...)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateInvocation indicates an expected call of UpdateInvocation.
func (mr *MockRecorderClientMockRecorder) UpdateInvocation(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateInvocation", reflect.TypeOf((*MockRecorderClient)(nil).UpdateInvocation), varargs...)
}

// MockRecorderServer is a mock of RecorderServer interface.
type MockRecorderServer struct {
	ctrl     *gomock.Controller
	recorder *MockRecorderServerMockRecorder
}

// MockRecorderServerMockRecorder is the mock recorder for MockRecorderServer.
type MockRecorderServerMockRecorder struct {
	mock *MockRecorderServer
}

// NewMockRecorderServer creates a new mock instance.
func NewMockRecorderServer(ctrl *gomock.Controller) *MockRecorderServer {
	mock := &MockRecorderServer{ctrl: ctrl}
	mock.recorder = &MockRecorderServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRecorderServer) EXPECT() *MockRecorderServerMockRecorder {
	return m.recorder
}

// BatchCreateArtifacts mocks base method.
func (m *MockRecorderServer) BatchCreateArtifacts(arg0 context.Context, arg1 *BatchCreateArtifactsRequest) (*BatchCreateArtifactsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BatchCreateArtifacts", arg0, arg1)
	ret0, _ := ret[0].(*BatchCreateArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateArtifacts indicates an expected call of BatchCreateArtifacts.
func (mr *MockRecorderServerMockRecorder) BatchCreateArtifacts(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateArtifacts", reflect.TypeOf((*MockRecorderServer)(nil).BatchCreateArtifacts), arg0, arg1)
}

// BatchCreateInvocations mocks base method.
func (m *MockRecorderServer) BatchCreateInvocations(arg0 context.Context, arg1 *BatchCreateInvocationsRequest) (*BatchCreateInvocationsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BatchCreateInvocations", arg0, arg1)
	ret0, _ := ret[0].(*BatchCreateInvocationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateInvocations indicates an expected call of BatchCreateInvocations.
func (mr *MockRecorderServerMockRecorder) BatchCreateInvocations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateInvocations", reflect.TypeOf((*MockRecorderServer)(nil).BatchCreateInvocations), arg0, arg1)
}

// BatchCreateTestExonerations mocks base method.
func (m *MockRecorderServer) BatchCreateTestExonerations(arg0 context.Context, arg1 *BatchCreateTestExonerationsRequest) (*BatchCreateTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BatchCreateTestExonerations", arg0, arg1)
	ret0, _ := ret[0].(*BatchCreateTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateTestExonerations indicates an expected call of BatchCreateTestExonerations.
func (mr *MockRecorderServerMockRecorder) BatchCreateTestExonerations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateTestExonerations", reflect.TypeOf((*MockRecorderServer)(nil).BatchCreateTestExonerations), arg0, arg1)
}

// BatchCreateTestResults mocks base method.
func (m *MockRecorderServer) BatchCreateTestResults(arg0 context.Context, arg1 *BatchCreateTestResultsRequest) (*BatchCreateTestResultsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BatchCreateTestResults", arg0, arg1)
	ret0, _ := ret[0].(*BatchCreateTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchCreateTestResults indicates an expected call of BatchCreateTestResults.
func (mr *MockRecorderServerMockRecorder) BatchCreateTestResults(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchCreateTestResults", reflect.TypeOf((*MockRecorderServer)(nil).BatchCreateTestResults), arg0, arg1)
}

// CreateInvocation mocks base method.
func (m *MockRecorderServer) CreateInvocation(arg0 context.Context, arg1 *CreateInvocationRequest) (*Invocation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateInvocation", arg0, arg1)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateInvocation indicates an expected call of CreateInvocation.
func (mr *MockRecorderServerMockRecorder) CreateInvocation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateInvocation", reflect.TypeOf((*MockRecorderServer)(nil).CreateInvocation), arg0, arg1)
}

// CreateTestExoneration mocks base method.
func (m *MockRecorderServer) CreateTestExoneration(arg0 context.Context, arg1 *CreateTestExonerationRequest) (*TestExoneration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTestExoneration", arg0, arg1)
	ret0, _ := ret[0].(*TestExoneration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTestExoneration indicates an expected call of CreateTestExoneration.
func (mr *MockRecorderServerMockRecorder) CreateTestExoneration(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTestExoneration", reflect.TypeOf((*MockRecorderServer)(nil).CreateTestExoneration), arg0, arg1)
}

// CreateTestResult mocks base method.
func (m *MockRecorderServer) CreateTestResult(arg0 context.Context, arg1 *CreateTestResultRequest) (*TestResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTestResult", arg0, arg1)
	ret0, _ := ret[0].(*TestResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTestResult indicates an expected call of CreateTestResult.
func (mr *MockRecorderServerMockRecorder) CreateTestResult(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTestResult", reflect.TypeOf((*MockRecorderServer)(nil).CreateTestResult), arg0, arg1)
}

// FinalizeInvocation mocks base method.
func (m *MockRecorderServer) FinalizeInvocation(arg0 context.Context, arg1 *FinalizeInvocationRequest) (*Invocation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FinalizeInvocation", arg0, arg1)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FinalizeInvocation indicates an expected call of FinalizeInvocation.
func (mr *MockRecorderServerMockRecorder) FinalizeInvocation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FinalizeInvocation", reflect.TypeOf((*MockRecorderServer)(nil).FinalizeInvocation), arg0, arg1)
}

// MarkInvocationSubmitted mocks base method.
func (m *MockRecorderServer) MarkInvocationSubmitted(arg0 context.Context, arg1 *MarkInvocationSubmittedRequest) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MarkInvocationSubmitted", arg0, arg1)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MarkInvocationSubmitted indicates an expected call of MarkInvocationSubmitted.
func (mr *MockRecorderServerMockRecorder) MarkInvocationSubmitted(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MarkInvocationSubmitted", reflect.TypeOf((*MockRecorderServer)(nil).MarkInvocationSubmitted), arg0, arg1)
}

// UpdateIncludedInvocations mocks base method.
func (m *MockRecorderServer) UpdateIncludedInvocations(arg0 context.Context, arg1 *UpdateIncludedInvocationsRequest) (*emptypb.Empty, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateIncludedInvocations", arg0, arg1)
	ret0, _ := ret[0].(*emptypb.Empty)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIncludedInvocations indicates an expected call of UpdateIncludedInvocations.
func (mr *MockRecorderServerMockRecorder) UpdateIncludedInvocations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIncludedInvocations", reflect.TypeOf((*MockRecorderServer)(nil).UpdateIncludedInvocations), arg0, arg1)
}

// UpdateInvocation mocks base method.
func (m *MockRecorderServer) UpdateInvocation(arg0 context.Context, arg1 *UpdateInvocationRequest) (*Invocation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateInvocation", arg0, arg1)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateInvocation indicates an expected call of UpdateInvocation.
func (mr *MockRecorderServerMockRecorder) UpdateInvocation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateInvocation", reflect.TypeOf((*MockRecorderServer)(nil).UpdateInvocation), arg0, arg1)
}
