package policy

import (
	"fmt"
	"sync"

	"cel.dev/cel-go/cel"
)

// celCostLimit bounds one evaluation. Expressions are operator-written but
// iterate over caller-supplied arguments, so a nested comprehension would
// otherwise cost whatever the caller makes it.
const celCostLimit = 1_000_000

var celEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)))
})

func compileCEL(expr string) (cel.Program, error) {
	env, err := celEnv()
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("must evaluate to a bool, not %s (compare with == true for a boolean argument)", ast.OutputType())
	}
	return env.Program(ast, cel.CostLimit(celCostLimit))
}

// celInput is the vocabulary an expression sees. identity is absent, not
// null, for an unauthenticated call; test it with has(request.identity).
func celInput(req Request) map[string]any {
	r := map[string]any{
		"method":    req.Method,
		"tool":      req.ToolName,
		"arguments": nonNilMap(req.Arguments),
		"transport": req.Transport,
		"target":    req.Target,
		"operation": req.Operation,
	}
	if id := req.Identity; id != nil {
		r["identity"] = map[string]any{
			"subject":  id.Subject,
			"issuer":   id.Issuer,
			"type":     string(id.Type),
			"provider": id.Provider,
			"scopes":   append([]string{}, id.Scopes...),
			"groups":   append([]string{}, id.Groups...),
			"claims":   nonNilMap(id.Claims),
		}
	}
	return map[string]any{"request": r}
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// evalCEL reports whether the expression matched. An error means it could not
// be decided: a missing key, a type mismatch, the cost limit.
func evalCEL(prg cel.Program, req Request) (bool, error) {
	out, _, err := prg.Eval(celInput(req))
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("evaluated to %T, not bool", out.Value())
	}
	return b, nil
}
