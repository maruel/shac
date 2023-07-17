// Copyright 2016 The LUCI Authors.
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

package prpc

// This file implements encoding of RPC results to HTTP responses.

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.chromium.org/luci/common/errors"
	"go.chromium.org/luci/common/logging"
	"go.chromium.org/luci/grpc/grpcutil"
)

const headerAccept = "Accept"

// responseFormat returns the format to be used in a response.
// Can return only FormatBinary (preferred), FormatJSONPB or FormatText.
// In case of an error, format is undefined.
func responseFormat(acceptHeader string) (Format, *protocolError) {
	if acceptHeader == "" {
		return FormatBinary, nil
	}

	parsed, err := parseAccept(acceptHeader)
	if err != nil {
		return FormatBinary, protocolErr(
			codes.InvalidArgument,
			http.StatusBadRequest,
			"bad Accept header: %s", err,
		)
	}
	formats := make(acceptFormatSlice, 0, len(parsed))
	for _, at := range parsed {
		f, err := FormatFromMediaType(at.Value)
		if err != nil {
			// Ignore invalid format. Check further.
			continue
		}
		formats = append(formats, acceptFormat{f, at.QualityFactor})
	}
	if len(formats) == 0 {
		return FormatBinary, protocolErr(
			codes.InvalidArgument,
			http.StatusNotAcceptable,
			"bad Accept header: specified media types are not not supported. Supported types: %q, %q, %q, %q.",
			FormatBinary.MediaType(),
			FormatJSONPB.MediaType(),
			FormatText.MediaType(),
			ContentTypeJSON,
		)
	}
	sort.Sort(formats) // order by quality factor and format preference.
	return formats[0].Format, nil
}

// marshalMessage marshals msg in the given format.
//
// If wrap is true and format is JSON, then prepends JSONPBPrefix and appends
// \n.
func marshalMessage(msg proto.Message, format Format, wrap bool) ([]byte, error) {
	if msg == nil {
		panic("msg is nil")
	}

	var buf bytes.Buffer
	switch format {

	case FormatBinary:
		return proto.Marshal(msg)

	case FormatJSONPB:
		if wrap {
			buf.WriteString(JSONPBPrefix)
		}
		m := jsonpb.Marshaler{}
		if err := m.Marshal(&buf, msg); err != nil {
			return nil, err
		}
		if wrap {
			buf.WriteRune('\n')
		}
		return buf.Bytes(), nil

	case FormatText:
		if err := proto.MarshalText(&buf, msg); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	default:
		panic(fmt.Errorf("impossible: invalid format %d", format))
	}
}

// writeMessage writes msg to w in the specified format.
// ctx is used to log errors.
// panics if msg is nil.
func writeMessage(ctx context.Context, w http.ResponseWriter, msg proto.Message, format Format, allowGZip bool) {
	if msg == nil {
		panic("msg is nil")
	}

	body, err := marshalMessage(msg, format, true)
	if err != nil {
		writeError(ctx, w, status.Error(codes.Internal, err.Error()), format)
		return
	}

	w.Header().Set(HeaderGRPCCode, strconv.Itoa(int(codes.OK)))
	w.Header().Set(headerContentType, format.MediaType())

	// Errors below most commonly happen if the client disconnects. The header
	// is already written. There is nothing more we can do other than just log
	// them.

	if allowGZip && len(body) > gzipThreshold {
		w.Header().Set("Content-Encoding", "gzip")

		gz := getGZipWriter(w)
		defer returnGZipWriter(gz)
		if _, err := gz.Write(body); err != nil {
			logging.Warningf(ctx, "prpc: failed to write or compress the response body: %s", err)
			return
		}
		if err := gz.Close(); err != nil {
			logging.Warningf(ctx, "prpc: failed to close gzip.Writer: %s", err)
			return
		}
	} else {
		if _, err := w.Write(body); err != nil {
			logging.Warningf(ctx, "prpc: failed to write response body: %s", err)
			return
		}
	}
}

func errorStatus(err error) (st *status.Status, httpStatus int) {
	if err == nil {
		panic("err is nil")
	}

	if perr, ok := err.(*protocolError); ok {
		st = status.New(perr.code, perr.err)
		httpStatus = perr.status
		return
	}

	err = errors.Unwrap(err)
	st, ok := status.FromError(err)
	switch {
	case ok:
	// great.

	case err == context.Canceled:
		st = status.New(codes.Canceled, "canceled")

	case err == context.DeadlineExceeded:
		st = status.New(codes.DeadlineExceeded, "deadline exceeded")

	default:
		// st is non-nil because err is non-nil.
	}

	httpStatus = grpcutil.CodeStatus(st.Code())
	return
}

func statusDetailsToHeaderValues(details []*anypb.Any, format Format) ([]string, error) {
	ret := make([]string, len(details))

	for i, det := range details {
		msgBytes, err := marshalMessage(det, format, false)
		if err != nil {
			return nil, err
		}

		ret[i] = base64.StdEncoding.EncodeToString(msgBytes)
	}

	return ret, nil
}

// writeError writes err to w and logs it.
func writeError(ctx context.Context, w http.ResponseWriter, err error, format Format) {
	st, httpStatus := errorStatus(err)

	// use st.Proto instead of st.Details to avoid unnecessary unmarshaling of
	// google.protobuf.Any underlying messages. We need Any protos themselves.
	detailHeader, err := statusDetailsToHeaderValues(st.Proto().Details, format)
	if err != nil {
		st = status.New(codes.Internal, "prpc: failed to write status details")
		httpStatus = http.StatusInternalServerError
	} else {
		w.Header()[HeaderStatusDetail] = detailHeader
	}

	body := st.Message()
	if httpStatus < 500 {
		logging.Warningf(ctx, "prpc: responding with %s error (HTTP %d): %s", st.Code(), httpStatus, st.Message())
	} else {
		// Hide potential implementation details from the user. Only codes that
		// result in HTTP status >= 500 are possible here.
		// See https://cloud.google.com/apis/design/errors.
		switch st.Code() {
		case codes.DataLoss:
			body = "Unrecoverable data loss or data corruption"
		case codes.Unknown:
			body = "Unknown server error"
		case codes.Internal:
			body = "Internal server error"
		case codes.Unimplemented:
			body = "API method not implemented by the server"
		case codes.Unavailable:
			body = "Service unavailable"
		case codes.DeadlineExceeded:
			body = "Request deadline exceeded"
		default:
			body = "Server error"
		}

		// Log everything about the error.
		logging.Errorf(ctx, "prpc: responding with %s error (HTTP %d): %s", st.Code(), httpStatus, st.Message())
		errors.Log(ctx, err)
	}

	w.Header().Set(HeaderGRPCCode, strconv.Itoa(int(st.Code())))
	w.Header().Set(headerContentType, "text/plain")
	w.WriteHeader(httpStatus)
	if _, err := io.WriteString(w, body); err != nil {
		// This error most commonly happens if the client disconnects. The header is
		// already written. There is nothing more we can do other than log it.
		logging.Warningf(ctx, "prpc: failed to write response body: %s", err)
		return
	}
	io.WriteString(w, "\n")
}
