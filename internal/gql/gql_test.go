package gql

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSummarizeExpandsFragments(t *testing.T) {
	ops, err := Summarize(`
mutation Sneaky { ...F  ... on Mutation { addComment(input:{}) { clientMutationId } } }
fragment F on Mutation { deleteRepository(input: {repositoryId: "x"}) { clientMutationId } }
query Q { viewer { login } }`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[0].Type != "mutation" || len(ops[0].Fields) != 2 || ops[0].Fields[0] != "deleteRepository" {
		t.Fatalf("%+v", ops)
	}
	if ops[1].Type != "query" || ops[1].Fields[0] != "viewer" {
		t.Fatalf("%+v", ops)
	}
}

func TestFromHTTPBatch(t *testing.T) {
	h := http.Header{"Content-Type": {"application/json"}}
	ops, err := FromHTTP("POST", nil, h, []byte(`[{"query":"{ viewer { login } }"},{"query":"mutation { mergePullRequest(input:{}) { clientMutationId } }"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[1].Fields[0] != "mergePullRequest" {
		t.Fatalf("%+v", ops)
	}
	if _, err := FromHTTP("POST", nil, h, []byte(`{"extensions":{"persistedQuery":{}}}`)); err == nil {
		t.Fatal("persisted query should error")
	}
}

func TestDuplicateQueryKeyRejected(t *testing.T) {
	h := http.Header{"Content-Type": {"application/json"}}
	for _, body := range []string{
		`{"query":"{ viewer { login } }","query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`,
		`[{"query":"{ a }"},{"query":"{ b }","query":"{ c }"}]`,
	} {
		if _, err := FromHTTP("POST", nil, h, []byte(body)); err == nil {
			t.Errorf("accepted duplicate keys: %s", body)
		}
	}
	if _, err := FromHTTP("POST", nil, h, []byte(`{"query":"{ a }","variables":{"query":"x","query2":"y"}}`)); err != nil {
		t.Errorf("nested keys are fine: %v", err)
	}
}

func TestFromHTTPResistsViewConfusion(t *testing.T) {
	jsonH := http.Header{"Content-Type": {"application/json"}}
	if _, err := FromHTTP("POST", nil, jsonH, []byte(`{"query":"mutation{destroy}","QUERY":"query{a}"}`)); err == nil {
		t.Error("case-variant duplicate key accepted")
	}
	ops, err := FromHTTP("POST", nil, jsonH, []byte(`{"_json":[{"query":"query{a}"},{"query":"mutation{destroy}"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[1].Type != "mutation" || ops[1].Fields[0] != "destroy" {
		t.Fatalf("_json not expanded: %+v", ops)
	}
	q := url.Values{"query": {"mutation{destroy}"}}
	ops, err = FromHTTP("POST", q, jsonH, []byte(`{"query":"query{a}"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[0].Fields[0] != "destroy" {
		t.Fatalf("URL query ignored: %+v", ops)
	}
	ops, err = FromHTTP("POST", url.Values{"query": {"mutation{destroy}"}}, http.Header{}, nil)
	if err != nil || len(ops) != 1 || ops[0].Type != "mutation" {
		t.Fatalf("url-only mutation: %+v %v", ops, err)
	}
	if _, err := FromHTTP("GET", url.Values{"query": {"query{a}", "mutation{destroy}"}}, http.Header{}, nil); err == nil {
		t.Error("repeated URL query accepted")
	}
}
