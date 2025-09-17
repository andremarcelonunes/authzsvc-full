package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// FieldSource represents where to extract a value from the request
type FieldSource struct {
	Source string `yaml:"source"` // "path", "query", "header", "body", "token"
	Name   string `yaml:"name"`   // field/parameter/claim name
}

// ValidationCondition represents a single field comparison rule
type ValidationCondition struct {
	RequestField FieldSource `yaml:"requestField"`
	TokenField   FieldSource `yaml:"tokenField"`
	Operator     string      `yaml:"operator"` // "equals", "notEquals", "in", "notIn", "contains", "exists"
	Description  string      `yaml:"description,omitempty"`
}

// ValidationRule defines comprehensive field validation rules for endpoints
type ValidationRule struct {
	Name        string                `yaml:"name"`
	Method      string                `yaml:"method"`
	Path        string                `yaml:"path"`
	Description string                `yaml:"description,omitempty"`
	Logic       string                `yaml:"logic"` // "all" (AND) or "any" (OR)
	Conditions  []ValidationCondition `yaml:"conditions"`
	Enabled     bool                  `yaml:"enabled"`
}

// ExtractValue extracts a value from request/token based on the field source
func (fs FieldSource) ExtractValue(c RequestContext, tokenClaims map[string]interface{}) (interface{}, error) {
	switch fs.Source {
	case "path":
		return c.GetPathParam(fs.Name), nil
	case "query":
		return c.GetQueryParam(fs.Name), nil
	case "header":
		return c.GetHeader(fs.Name), nil
	case "body":
		return c.GetBodyField(fs.Name)
	case "token":
		if claim, exists := tokenClaims[fs.Name]; exists {
			return claim, nil
		}
		return nil, fmt.Errorf("token claim '%s' not found", fs.Name)
	default:
		return nil, fmt.Errorf("unsupported field source: %s", fs.Source)
	}
}

// RequestContext interface for extracting values from HTTP requests
type RequestContext interface {
	GetPathParam(name string) string
	GetQueryParam(name string) string
	GetHeader(name string) string
	GetBodyField(name string) (interface{}, error)
}

// CompareValues performs comparison based on the operator
func (vc ValidationCondition) CompareValues(reqValue, tokenValue interface{}) (bool, error) {
	switch vc.Operator {
	case "equals":
		return compareEquals(reqValue, tokenValue), nil
	case "notEquals":
		return !compareEquals(reqValue, tokenValue), nil
	case "in":
		return compareIn(reqValue, tokenValue), nil
	case "notIn":
		return !compareIn(reqValue, tokenValue), nil
	case "contains":
		return compareContains(reqValue, tokenValue), nil
	case "exists":
		return reqValue != nil && reqValue != "", nil
	default:
		return false, fmt.Errorf("unsupported operator: %s", vc.Operator)
	}
}

// Validate evaluates all conditions in the rule
func (vr ValidationRule) Validate(c RequestContext, tokenClaims map[string]interface{}) (bool, error) {
	if !vr.Enabled {
		return true, nil // Skip disabled rules
	}

	if len(vr.Conditions) == 0 {
		return true, nil // No conditions means pass
	}

	results := make([]bool, len(vr.Conditions))
	
	for i, condition := range vr.Conditions {
		// Extract request value
		reqValue, err := condition.RequestField.ExtractValue(c, tokenClaims)
		if err != nil {
			return false, fmt.Errorf("failed to extract request field %s.%s: %w", 
				condition.RequestField.Source, condition.RequestField.Name, err)
		}

		// Extract token value
		tokenValue, err := condition.TokenField.ExtractValue(c, tokenClaims)
		if err != nil {
			return false, fmt.Errorf("failed to extract token field %s.%s: %w", 
				condition.TokenField.Source, condition.TokenField.Name, err)
		}

		// Compare values
		match, err := condition.CompareValues(reqValue, tokenValue)
		if err != nil {
			return false, fmt.Errorf("comparison failed for condition %d: %w", i, err)
		}

		results[i] = match
	}

	// Apply logic (AND/OR)
	switch vr.Logic {
	case "any", "or":
		for _, result := range results {
			if result {
				return true, nil
			}
		}
		return false, nil
	case "all", "and", "":
		for _, result := range results {
			if !result {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported logic operator: %s", vr.Logic)
	}
}

// Helper comparison functions
func compareEquals(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == b
	}
	
	// Convert to strings for comparison to handle type mismatches
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	return aStr == bStr
}

func compareIn(needle, haystack interface{}) bool {
	if needle == nil || haystack == nil {
		return false
	}

	// Handle different haystack types
	switch h := haystack.(type) {
	case []interface{}:
		needleStr := fmt.Sprintf("%v", needle)
		for _, item := range h {
			if fmt.Sprintf("%v", item) == needleStr {
				return true
			}
		}
	case []string:
		needleStr := fmt.Sprintf("%v", needle)
		for _, item := range h {
			if item == needleStr {
				return true
			}
		}
	case string:
		// Check if needle is a substring of haystack
		return strings.Contains(h, fmt.Sprintf("%v", needle))
	default:
		// Try to parse as JSON array
		if haystackStr, ok := haystack.(string); ok {
			var arr []interface{}
			if err := json.Unmarshal([]byte(haystackStr), &arr); err == nil {
				return compareIn(needle, arr)
			}
		}
	}
	
	return false
}

func compareContains(container, item interface{}) bool {
	if container == nil || item == nil {
		return false
	}

	containerStr := fmt.Sprintf("%v", container)
	itemStr := fmt.Sprintf("%v", item)
	return strings.Contains(containerStr, itemStr)
}

// ConvertValue attempts to convert a value to the expected type
func ConvertValue(value interface{}, targetType reflect.Type) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	valueStr := fmt.Sprintf("%v", value)

	switch targetType.Kind() {
	case reflect.String:
		return valueStr, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.ParseInt(valueStr, 10, 64)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.ParseUint(valueStr, 10, 64)
	case reflect.Float32, reflect.Float64:
		return strconv.ParseFloat(valueStr, 64)
	case reflect.Bool:
		return strconv.ParseBool(valueStr)
	default:
		return value, nil
	}
}