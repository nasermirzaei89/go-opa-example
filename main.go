package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"net/http"
)

var (
	//go:embed policy.rego
	policy string
)

func main() {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("x = data.authz.allow"),
		rego.Module("authz.rego", policy),
	).PrepareForEval(ctx)
	if err != nil {
		panic(fmt.Errorf("error on new rego: %w", err))
	}

	http.HandleFunc("/restricted", func(w http.ResponseWriter, r *http.Request) {
		results, err := query.Eval(r.Context(), rego.EvalInput(map[string]any{
			"path":   r.URL.Path,
			"method": r.Method,
			"user":   r.URL.Query().Get("user"),
		}))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Errorf("error on evaluation: %w", err).Error()))
			return
		}

		if len(results) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("no authorization result"))
			return
		}

		result, ok := results[0].Bindings["x"].(bool)
		if !ok || !result {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("access denied"))
			return
		}

		_, _ = w.Write([]byte("access granted"))
	})

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(fmt.Errorf("error on listen and serve http: %w", err))
	}
}
