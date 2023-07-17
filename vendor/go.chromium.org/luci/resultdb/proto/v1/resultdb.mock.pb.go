// Code generated by MockGen. DO NOT EDIT.
// Source: resultdb.pb.go

package resultpb

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockResultDBClient is a mock of ResultDBClient interface.
type MockResultDBClient struct {
	ctrl     *gomock.Controller
	recorder *MockResultDBClientMockRecorder
}

// MockResultDBClientMockRecorder is the mock recorder for MockResultDBClient.
type MockResultDBClientMockRecorder struct {
	mock *MockResultDBClient
}

// NewMockResultDBClient creates a new mock instance.
func NewMockResultDBClient(ctrl *gomock.Controller) *MockResultDBClient {
	mock := &MockResultDBClient{ctrl: ctrl}
	mock.recorder = &MockResultDBClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResultDBClient) EXPECT() *MockResultDBClientMockRecorder {
	return m.recorder
}

// BatchGetTestVariants mocks base method.
func (m *MockResultDBClient) BatchGetTestVariants(ctx context.Context, in *BatchGetTestVariantsRequest, opts ...grpc.CallOption) (*BatchGetTestVariantsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "BatchGetTestVariants", varargs...)
	ret0, _ := ret[0].(*BatchGetTestVariantsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchGetTestVariants indicates an expected call of BatchGetTestVariants.
func (mr *MockResultDBClientMockRecorder) BatchGetTestVariants(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchGetTestVariants", reflect.TypeOf((*MockResultDBClient)(nil).BatchGetTestVariants), varargs...)
}

// GetArtifact mocks base method.
func (m *MockResultDBClient) GetArtifact(ctx context.Context, in *GetArtifactRequest, opts ...grpc.CallOption) (*Artifact, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetArtifact", varargs...)
	ret0, _ := ret[0].(*Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetArtifact indicates an expected call of GetArtifact.
func (mr *MockResultDBClientMockRecorder) GetArtifact(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetArtifact", reflect.TypeOf((*MockResultDBClient)(nil).GetArtifact), varargs...)
}

// GetInvocation mocks base method.
func (m *MockResultDBClient) GetInvocation(ctx context.Context, in *GetInvocationRequest, opts ...grpc.CallOption) (*Invocation, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetInvocation", varargs...)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInvocation indicates an expected call of GetInvocation.
func (mr *MockResultDBClientMockRecorder) GetInvocation(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInvocation", reflect.TypeOf((*MockResultDBClient)(nil).GetInvocation), varargs...)
}

// GetTestExoneration mocks base method.
func (m *MockResultDBClient) GetTestExoneration(ctx context.Context, in *GetTestExonerationRequest, opts ...grpc.CallOption) (*TestExoneration, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetTestExoneration", varargs...)
	ret0, _ := ret[0].(*TestExoneration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTestExoneration indicates an expected call of GetTestExoneration.
func (mr *MockResultDBClientMockRecorder) GetTestExoneration(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTestExoneration", reflect.TypeOf((*MockResultDBClient)(nil).GetTestExoneration), varargs...)
}

// GetTestResult mocks base method.
func (m *MockResultDBClient) GetTestResult(ctx context.Context, in *GetTestResultRequest, opts ...grpc.CallOption) (*TestResult, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetTestResult", varargs...)
	ret0, _ := ret[0].(*TestResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTestResult indicates an expected call of GetTestResult.
func (mr *MockResultDBClientMockRecorder) GetTestResult(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTestResult", reflect.TypeOf((*MockResultDBClient)(nil).GetTestResult), varargs...)
}

// ListArtifacts mocks base method.
func (m *MockResultDBClient) ListArtifacts(ctx context.Context, in *ListArtifactsRequest, opts ...grpc.CallOption) (*ListArtifactsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListArtifacts", varargs...)
	ret0, _ := ret[0].(*ListArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListArtifacts indicates an expected call of ListArtifacts.
func (mr *MockResultDBClientMockRecorder) ListArtifacts(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListArtifacts", reflect.TypeOf((*MockResultDBClient)(nil).ListArtifacts), varargs...)
}

// ListTestExonerations mocks base method.
func (m *MockResultDBClient) ListTestExonerations(ctx context.Context, in *ListTestExonerationsRequest, opts ...grpc.CallOption) (*ListTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListTestExonerations", varargs...)
	ret0, _ := ret[0].(*ListTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTestExonerations indicates an expected call of ListTestExonerations.
func (mr *MockResultDBClientMockRecorder) ListTestExonerations(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTestExonerations", reflect.TypeOf((*MockResultDBClient)(nil).ListTestExonerations), varargs...)
}

// ListTestResults mocks base method.
func (m *MockResultDBClient) ListTestResults(ctx context.Context, in *ListTestResultsRequest, opts ...grpc.CallOption) (*ListTestResultsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListTestResults", varargs...)
	ret0, _ := ret[0].(*ListTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTestResults indicates an expected call of ListTestResults.
func (mr *MockResultDBClientMockRecorder) ListTestResults(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTestResults", reflect.TypeOf((*MockResultDBClient)(nil).ListTestResults), varargs...)
}

// QueryArtifacts mocks base method.
func (m *MockResultDBClient) QueryArtifacts(ctx context.Context, in *QueryArtifactsRequest, opts ...grpc.CallOption) (*QueryArtifactsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryArtifacts", varargs...)
	ret0, _ := ret[0].(*QueryArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryArtifacts indicates an expected call of QueryArtifacts.
func (mr *MockResultDBClientMockRecorder) QueryArtifacts(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryArtifacts", reflect.TypeOf((*MockResultDBClient)(nil).QueryArtifacts), varargs...)
}

// QueryTestExonerations mocks base method.
func (m *MockResultDBClient) QueryTestExonerations(ctx context.Context, in *QueryTestExonerationsRequest, opts ...grpc.CallOption) (*QueryTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryTestExonerations", varargs...)
	ret0, _ := ret[0].(*QueryTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestExonerations indicates an expected call of QueryTestExonerations.
func (mr *MockResultDBClientMockRecorder) QueryTestExonerations(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestExonerations", reflect.TypeOf((*MockResultDBClient)(nil).QueryTestExonerations), varargs...)
}

// QueryTestResultStatistics mocks base method.
func (m *MockResultDBClient) QueryTestResultStatistics(ctx context.Context, in *QueryTestResultStatisticsRequest, opts ...grpc.CallOption) (*QueryTestResultStatisticsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryTestResultStatistics", varargs...)
	ret0, _ := ret[0].(*QueryTestResultStatisticsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestResultStatistics indicates an expected call of QueryTestResultStatistics.
func (mr *MockResultDBClientMockRecorder) QueryTestResultStatistics(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestResultStatistics", reflect.TypeOf((*MockResultDBClient)(nil).QueryTestResultStatistics), varargs...)
}

// QueryTestResults mocks base method.
func (m *MockResultDBClient) QueryTestResults(ctx context.Context, in *QueryTestResultsRequest, opts ...grpc.CallOption) (*QueryTestResultsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryTestResults", varargs...)
	ret0, _ := ret[0].(*QueryTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestResults indicates an expected call of QueryTestResults.
func (mr *MockResultDBClientMockRecorder) QueryTestResults(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestResults", reflect.TypeOf((*MockResultDBClient)(nil).QueryTestResults), varargs...)
}

// QueryTestVariants mocks base method.
func (m *MockResultDBClient) QueryTestVariants(ctx context.Context, in *QueryTestVariantsRequest, opts ...grpc.CallOption) (*QueryTestVariantsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "QueryTestVariants", varargs...)
	ret0, _ := ret[0].(*QueryTestVariantsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestVariants indicates an expected call of QueryTestVariants.
func (mr *MockResultDBClientMockRecorder) QueryTestVariants(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestVariants", reflect.TypeOf((*MockResultDBClient)(nil).QueryTestVariants), varargs...)
}

// MockResultDBServer is a mock of ResultDBServer interface.
type MockResultDBServer struct {
	ctrl     *gomock.Controller
	recorder *MockResultDBServerMockRecorder
}

// MockResultDBServerMockRecorder is the mock recorder for MockResultDBServer.
type MockResultDBServerMockRecorder struct {
	mock *MockResultDBServer
}

// NewMockResultDBServer creates a new mock instance.
func NewMockResultDBServer(ctrl *gomock.Controller) *MockResultDBServer {
	mock := &MockResultDBServer{ctrl: ctrl}
	mock.recorder = &MockResultDBServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResultDBServer) EXPECT() *MockResultDBServerMockRecorder {
	return m.recorder
}

// BatchGetTestVariants mocks base method.
func (m *MockResultDBServer) BatchGetTestVariants(arg0 context.Context, arg1 *BatchGetTestVariantsRequest) (*BatchGetTestVariantsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BatchGetTestVariants", arg0, arg1)
	ret0, _ := ret[0].(*BatchGetTestVariantsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BatchGetTestVariants indicates an expected call of BatchGetTestVariants.
func (mr *MockResultDBServerMockRecorder) BatchGetTestVariants(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchGetTestVariants", reflect.TypeOf((*MockResultDBServer)(nil).BatchGetTestVariants), arg0, arg1)
}

// GetArtifact mocks base method.
func (m *MockResultDBServer) GetArtifact(arg0 context.Context, arg1 *GetArtifactRequest) (*Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetArtifact", arg0, arg1)
	ret0, _ := ret[0].(*Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetArtifact indicates an expected call of GetArtifact.
func (mr *MockResultDBServerMockRecorder) GetArtifact(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetArtifact", reflect.TypeOf((*MockResultDBServer)(nil).GetArtifact), arg0, arg1)
}

// GetInvocation mocks base method.
func (m *MockResultDBServer) GetInvocation(arg0 context.Context, arg1 *GetInvocationRequest) (*Invocation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInvocation", arg0, arg1)
	ret0, _ := ret[0].(*Invocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInvocation indicates an expected call of GetInvocation.
func (mr *MockResultDBServerMockRecorder) GetInvocation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInvocation", reflect.TypeOf((*MockResultDBServer)(nil).GetInvocation), arg0, arg1)
}

// GetTestExoneration mocks base method.
func (m *MockResultDBServer) GetTestExoneration(arg0 context.Context, arg1 *GetTestExonerationRequest) (*TestExoneration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTestExoneration", arg0, arg1)
	ret0, _ := ret[0].(*TestExoneration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTestExoneration indicates an expected call of GetTestExoneration.
func (mr *MockResultDBServerMockRecorder) GetTestExoneration(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTestExoneration", reflect.TypeOf((*MockResultDBServer)(nil).GetTestExoneration), arg0, arg1)
}

// GetTestResult mocks base method.
func (m *MockResultDBServer) GetTestResult(arg0 context.Context, arg1 *GetTestResultRequest) (*TestResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTestResult", arg0, arg1)
	ret0, _ := ret[0].(*TestResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTestResult indicates an expected call of GetTestResult.
func (mr *MockResultDBServerMockRecorder) GetTestResult(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTestResult", reflect.TypeOf((*MockResultDBServer)(nil).GetTestResult), arg0, arg1)
}

// ListArtifacts mocks base method.
func (m *MockResultDBServer) ListArtifacts(arg0 context.Context, arg1 *ListArtifactsRequest) (*ListArtifactsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListArtifacts", arg0, arg1)
	ret0, _ := ret[0].(*ListArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListArtifacts indicates an expected call of ListArtifacts.
func (mr *MockResultDBServerMockRecorder) ListArtifacts(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListArtifacts", reflect.TypeOf((*MockResultDBServer)(nil).ListArtifacts), arg0, arg1)
}

// ListTestExonerations mocks base method.
func (m *MockResultDBServer) ListTestExonerations(arg0 context.Context, arg1 *ListTestExonerationsRequest) (*ListTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTestExonerations", arg0, arg1)
	ret0, _ := ret[0].(*ListTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTestExonerations indicates an expected call of ListTestExonerations.
func (mr *MockResultDBServerMockRecorder) ListTestExonerations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTestExonerations", reflect.TypeOf((*MockResultDBServer)(nil).ListTestExonerations), arg0, arg1)
}

// ListTestResults mocks base method.
func (m *MockResultDBServer) ListTestResults(arg0 context.Context, arg1 *ListTestResultsRequest) (*ListTestResultsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTestResults", arg0, arg1)
	ret0, _ := ret[0].(*ListTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTestResults indicates an expected call of ListTestResults.
func (mr *MockResultDBServerMockRecorder) ListTestResults(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTestResults", reflect.TypeOf((*MockResultDBServer)(nil).ListTestResults), arg0, arg1)
}

// QueryArtifacts mocks base method.
func (m *MockResultDBServer) QueryArtifacts(arg0 context.Context, arg1 *QueryArtifactsRequest) (*QueryArtifactsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryArtifacts", arg0, arg1)
	ret0, _ := ret[0].(*QueryArtifactsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryArtifacts indicates an expected call of QueryArtifacts.
func (mr *MockResultDBServerMockRecorder) QueryArtifacts(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryArtifacts", reflect.TypeOf((*MockResultDBServer)(nil).QueryArtifacts), arg0, arg1)
}

// QueryTestExonerations mocks base method.
func (m *MockResultDBServer) QueryTestExonerations(arg0 context.Context, arg1 *QueryTestExonerationsRequest) (*QueryTestExonerationsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryTestExonerations", arg0, arg1)
	ret0, _ := ret[0].(*QueryTestExonerationsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestExonerations indicates an expected call of QueryTestExonerations.
func (mr *MockResultDBServerMockRecorder) QueryTestExonerations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestExonerations", reflect.TypeOf((*MockResultDBServer)(nil).QueryTestExonerations), arg0, arg1)
}

// QueryTestResultStatistics mocks base method.
func (m *MockResultDBServer) QueryTestResultStatistics(arg0 context.Context, arg1 *QueryTestResultStatisticsRequest) (*QueryTestResultStatisticsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryTestResultStatistics", arg0, arg1)
	ret0, _ := ret[0].(*QueryTestResultStatisticsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestResultStatistics indicates an expected call of QueryTestResultStatistics.
func (mr *MockResultDBServerMockRecorder) QueryTestResultStatistics(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestResultStatistics", reflect.TypeOf((*MockResultDBServer)(nil).QueryTestResultStatistics), arg0, arg1)
}

// QueryTestResults mocks base method.
func (m *MockResultDBServer) QueryTestResults(arg0 context.Context, arg1 *QueryTestResultsRequest) (*QueryTestResultsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryTestResults", arg0, arg1)
	ret0, _ := ret[0].(*QueryTestResultsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestResults indicates an expected call of QueryTestResults.
func (mr *MockResultDBServerMockRecorder) QueryTestResults(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestResults", reflect.TypeOf((*MockResultDBServer)(nil).QueryTestResults), arg0, arg1)
}

// QueryTestVariants mocks base method.
func (m *MockResultDBServer) QueryTestVariants(arg0 context.Context, arg1 *QueryTestVariantsRequest) (*QueryTestVariantsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryTestVariants", arg0, arg1)
	ret0, _ := ret[0].(*QueryTestVariantsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryTestVariants indicates an expected call of QueryTestVariants.
func (mr *MockResultDBServerMockRecorder) QueryTestVariants(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryTestVariants", reflect.TypeOf((*MockResultDBServer)(nil).QueryTestVariants), arg0, arg1)
}
