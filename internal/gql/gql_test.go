package gql

import (
	"net/http"
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
