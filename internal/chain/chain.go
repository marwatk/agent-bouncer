package chain

import (
	"context"
	"fmt"
)

// Handler processes a request, typically by calling the rest of the chain.
type Handler func(*Request) (*Response, error)

// Filter is one link in the chain. Like a servlet filter it may inspect or
// modify the request, short-circuit with a denial or synthetic response, or
// call next and post-process the response.
type Filter interface {
	Name() string
	Handle(req *Request, next Handler) (*Response, error)
}

// Approver asks a human to approve a request.
type Approver interface {
	Ask(ctx context.Context, a AskRequest) (bool, error)
}

// AskRequest is a pending human decision.
type AskRequest struct {
	Session *Session
	Filter  string
	Prompt  string
	// Key identifies the decision for "allow for this session". It defaults
	// to the prompt plus the request, so a remembered answer covers only
	// identical requests; filters pass a key to group requests on purpose.
	Key     string
	Request string
}

// Logger receives filter log output.
type Logger func(filter, msg string, fields map[string]any)

// ProjectResolver maps a GitLab project path to its numeric ID on a host.
type ProjectResolver func(ctx context.Context, service, host, project string) (int64, error)

// Env is shared by every filter in a daemon.
type Env struct {
	Approver Approver
	Log      Logger
	Resolver ProjectResolver
}

// Build composes filters around terminal. A filter error or panic fails
// closed: the request is denied, attributed to the failing filter.
func Build(filters []Filter, terminal Handler) Handler {
	h := terminal
	for i := len(filters) - 1; i >= 0; i-- {
		f, next := filters[i], h
		h = func(req *Request) (resp *Response, err error) {
			defer func() {
				if p := recover(); p != nil {
					resp, err = Deny(f.Name(), fmt.Sprintf("filter panic: %v", p)), nil
				}
			}()
			resp, err = f.Handle(req, next)
			if err != nil {
				return Deny(f.Name(), "filter error: "+err.Error()), nil
			}
			if resp == nil {
				return Deny(f.Name(), "filter returned no response"), nil
			}
			return resp, nil
		}
	}
	return h
}
