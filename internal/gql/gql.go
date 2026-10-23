// Package gql summarizes GraphQL requests for policy: operation types and
// top-level fields, with fragments expanded so fields can't hide in spreads.
package gql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Operation is one operation in a GraphQL document.
type Operation struct {
	Type   string   `json:"type"` // query, mutation, subscription
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// Summarize parses a GraphQL document. Every operation in the document is
// returned, not just the one named by operationName, so policy is evaluated
// conservatively.
func Summarize(query string) ([]Operation, error) {
	doc, err := parser.ParseQuery(&ast.Source{Input: query})
	if err != nil {
		return nil, fmt.Errorf("graphql parse: %w", err)
	}
	if len(doc.Operations) == 0 {
		return nil, errors.New("graphql: no operations")
	}
	var ops []Operation
	for _, op := range doc.Operations {
		seen := map[string]bool{}
		var fields []string
		if err := collect(op.SelectionSet, doc.Fragments, map[string]bool{}, seen, &fields); err != nil {
			return nil, err
		}
		ops = append(ops, Operation{Type: string(op.Operation), Name: op.Name, Fields: fields})
	}
	return ops, nil
}

func collect(set ast.SelectionSet, frags ast.FragmentDefinitionList, visiting, seen map[string]bool, out *[]string) error {
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Name == "__typename" || seen[s.Name] {
				continue
			}
			seen[s.Name] = true
			*out = append(*out, s.Name)
		case *ast.InlineFragment:
			if err := collect(s.SelectionSet, frags, visiting, seen, out); err != nil {
				return err
			}
		case *ast.FragmentSpread:
			if visiting[s.Name] {
				return fmt.Errorf("graphql: fragment cycle at %q", s.Name)
			}
			f := frags.ForName(s.Name)
			if f == nil {
				return fmt.Errorf("graphql: unknown fragment %q", s.Name)
			}
			visiting[s.Name] = true
			if err := collect(f.SelectionSet, frags, visiting, seen, out); err != nil {
				return err
			}
			delete(visiting, s.Name)
		}
	}
	return nil
}

// FromHTTP extracts and summarizes the GraphQL operations in an HTTP request.
// It returns (nil, nil) if the request does not carry a GraphQL query.
func FromHTTP(method string, query url.Values, header http.Header, body []byte) ([]Operation, error) {
	// A query in the URL is run by servers (GitLab, GitHub) on any method,
	// so inspect it whatever the method is. Ambiguity (more than one value)
	// fails closed.
	if qs, ok := query["query"]; ok {
		if len(qs) != 1 {
			return nil, errors.New("graphql: query given more than once in the URL")
		}
		urlOps, err := Summarize(qs[0])
		if err != nil {
			return nil, err
		}
		bodyOps, err := fromBody(method, header, body)
		if err != nil {
			return nil, err
		}
		return append(urlOps, bodyOps...), nil
	}
	return fromBody(method, header, body)
}

func fromBody(method string, header http.Header, body []byte) ([]Operation, error) {
	if method == http.MethodGet {
		return nil, nil
	}
	ct, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if ct == "application/graphql" {
		return Summarize(string(body))
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	if err := checkKeys(body); err != nil {
		return nil, err
	}
	// Decode into RawMessage maps so a case-variant key (QUERY) can't shadow
	// the real one and so the GitLab _json multiplex key is seen.
	var objs []map[string]json.RawMessage
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(body, &objs); err != nil {
			return nil, fmt.Errorf("graphql: batch body: %w", err)
		}
	} else {
		var o map[string]json.RawMessage
		if err := json.Unmarshal(body, &o); err != nil {
			return nil, fmt.Errorf("graphql: body: %w", err)
		}
		objs = []map[string]json.RawMessage{o}
	}
	var all []Operation
	for _, o := range objs {
		ops, err := opsFromObject(o)
		if err != nil {
			return nil, err
		}
		all = append(all, ops...)
	}
	return all, nil
}

// opsFromObject extracts operations from one GraphQL request object,
// including a GitLab `_json` multiplex array.
func opsFromObject(o map[string]json.RawMessage) ([]Operation, error) {
	if raw, ok := o["_json"]; ok {
		var batch []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("graphql: _json: %w", err)
		}
		var all []Operation
		for _, e := range batch {
			ops, err := opsFromObject(e)
			if err != nil {
				return nil, err
			}
			all = append(all, ops...)
		}
		return all, nil
	}
	raw, ok := o["query"]
	if !ok {
		return nil, errors.New("graphql: request has no query text (persisted query?)")
	}
	var q string
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, fmt.Errorf("graphql: query: %w", err)
	}
	if q == "" {
		return nil, errors.New("graphql: request has no query text (persisted query?)")
	}
	return Summarize(q)
}

// checkKeys rejects a request object (or batch of them) whose top-level keys
// collide case-insensitively. JSON parsers disagree on which wins, so a
// QUERY key could shadow the query bouncer inspects.
func checkKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("graphql: body: %w", err)
	}
	checkObject := func() error {
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("graphql: body: %w", err)
			}
			k, _ := kt.(string)
			lk := strings.ToLower(k)
			if seen[lk] {
				return fmt.Errorf("graphql: duplicate %q key in request body", k)
			}
			seen[lk] = true
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("graphql: body: %w", err)
			}
		}
		_, err := dec.Token() // closing brace
		return err
	}
	switch tok {
	case json.Delim('{'):
		return checkObject()
	case json.Delim('['):
		for dec.More() {
			t, err := dec.Token()
			if err != nil {
				return fmt.Errorf("graphql: body: %w", err)
			}
			if t != json.Delim('{') {
				return errors.New("graphql: batch entries must be objects")
			}
			if err := checkObject(); err != nil {
				return err
			}
		}
	}
	return nil
}
