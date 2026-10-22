// Package gql summarizes GraphQL requests for policy: operation types and
// top-level fields, with fragments expanded so fields can't hide in spreads.
package gql

import (
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
	if method == http.MethodGet {
		q := query.Get("query")
		if q == "" {
			return nil, nil
		}
		return Summarize(q)
	}
	ct, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if ct == "application/graphql" {
		return Summarize(string(body))
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	type payload struct {
		Query string `json:"query"`
	}
	var docs []payload
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(body, &docs); err != nil {
			return nil, fmt.Errorf("graphql: batch body: %w", err)
		}
	} else {
		var p payload
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("graphql: body: %w", err)
		}
		docs = []payload{p}
	}
	var all []Operation
	for _, d := range docs {
		if d.Query == "" {
			// Persisted queries (hash only) can't be inspected.
			return nil, errors.New("graphql: request has no query text (persisted query?)")
		}
		ops, err := Summarize(d.Query)
		if err != nil {
			return nil, err
		}
		all = append(all, ops...)
	}
	return all, nil
}
