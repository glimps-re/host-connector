package handler

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/glimps-re/host-connector/pkg/config"
)

// unknownKeys lists the keys of the JSON raw that config.Config does not
// declare, as dotted paths. An undecodable raw gives none: the caller has
// already refused it.
func unknownKeys(raw json.RawMessage) []string {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var unknown []string
	collectUnknown("", doc, reflect.TypeFor[config.Config](), &unknown)
	sort.Strings(unknown)
	return unknown
}

func collectUnknown(prefix string, doc map[string]json.RawMessage, t reflect.Type, out *[]string) {
	fields := jsonFields(t)
	for key, value := range doc {
		name := prefix + key
		field, ok := fields[strings.ToLower(key)]
		if !ok {
			*out = append(*out, name)
			continue
		}
		ft := field
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() != reflect.Struct {
			continue
		}
		var sub map[string]json.RawMessage
		if json.Unmarshal(value, &sub) == nil {
			collectUnknown(name+".", sub, ft, out)
		}
	}
}

// jsonFields maps the JSON key of each field of struct type t, embedded
// structs flattened as encoding/json does, to the type of the field.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range jsonFields(ft) {
					fields[k] = v
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		// encoding/json matches keys without regard to case.
		fields[strings.ToLower(name)] = f.Type
	}
	return fields
}
