//go:build linux

package main

import (
	"bytes"
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	maxFormDepth = 4
	maxDecoded   = 256 << 20
)

// pdfPageTexts returns the text of each page, read with pdfcpu from the content
// streams (and the form XObjects they paint) through the ToUnicode map of the
// Type0 fonts. Spaces may be lost: match with regexps.
func pdfPageTexts(tb testing.TB, pdf []byte) []string {
	tb.Helper()
	conf, err := api.LoadConfiguration(api.ConfigurationOptions{Mode: api.ConfigurationModeStateless})
	if err != nil {
		tb.Fatalf("pdfcpu configuration: %v", err)
	}
	ctx, err := api.ReadContext(context.Background(), bytes.NewReader(pdf), conf)
	if err != nil {
		tb.Fatalf("reading the PDF: %v", err)
	}
	if err := ctx.EnsurePageCount(); err != nil {
		tb.Fatalf("counting the pages: %v", err)
	}
	r := &textReader{tb: tb, ctx: ctx, cmaps: map[types.IndirectRef]map[uint16]string{}}
	texts := make([]string, 0, ctx.PageCount)
	for n := 1; n <= ctx.PageCount; n++ {
		page, _, inh, err := ctx.PageDict(context.Background(), n, true)
		if err != nil {
			tb.Fatalf("page %d: %v", n, err)
		}
		content, err := ctx.PageContent(page, n)
		if err != nil {
			tb.Fatalf("content of page %d: %v", n, err)
		}
		texts = append(texts, r.text(content, inh.Resources, 0))
	}
	return texts
}

type textReader struct {
	tb    testing.TB
	ctx   *model.Context
	cmaps map[types.IndirectRef]map[uint16]string
}

func (r *textReader) text(content []byte, res types.Dict, depth int) string {
	r.tb.Helper()
	fonts := r.fonts(res)
	xobjects := r.dict(res["XObject"])
	var (
		out      strings.Builder
		cur      map[uint16]string
		operands []token
	)
	for _, tk := range tokenize(r.tb, content) {
		if tk.kind != tokOp {
			operands = append(operands, tk)
			continue
		}
		switch tk.val {
		case "BT", "ET":
			out.WriteByte('\n')
		case "Tf":
			if len(operands) >= 2 {
				cur = fonts[operands[len(operands)-2].val]
			}
		case "Tj", "TJ", "'", "\"":
			for _, o := range operands {
				if o.kind == tokString {
					out.WriteString(decodeGlyphs(o.val, cur))
				}
			}
		case "Do":
			if len(operands) == 1 && depth < maxFormDepth {
				r.form(&out, xobjects[operands[0].val], depth)
			}
		}
		operands = operands[:0]
	}
	return out.String()
}

func (r *textReader) form(out *strings.Builder, ref types.Object, depth int) {
	sd, _, err := r.ctx.DereferenceStreamDict(ref)
	if err != nil || sd == nil {
		return
	}
	if st, _ := sd.Dict["Subtype"].(types.Name); st != "Form" {
		return
	}
	if err := sd.DecodeWithLimit(maxDecoded); err != nil {
		r.tb.Fatalf("decoding a form XObject: %v", err)
	}
	out.WriteString(r.text(sd.Content, r.dict(sd.Dict["Resources"]), depth+1))
}

func (r *textReader) dict(o types.Object) types.Dict {
	if o == nil {
		return nil
	}
	d, err := r.ctx.DereferenceDict(o)
	if err != nil {
		r.tb.Fatalf("dereferencing a dictionary: %v", err)
	}
	return d
}

// fonts maps each font resource name to its glyph → text map.
func (r *textReader) fonts(res types.Dict) map[string]map[uint16]string {
	out := map[string]map[uint16]string{}
	for name, ref := range r.dict(res["Font"]) {
		out[name] = r.cmap(ref)
	}
	return out
}

func (r *textReader) cmap(ref types.Object) map[uint16]string {
	if ir, ok := ref.(types.IndirectRef); ok {
		if m, ok := r.cmaps[ir]; ok {
			return m
		}
	}
	font := r.dict(ref)
	sd, _, err := r.ctx.DereferenceStreamDict(font["ToUnicode"])
	if err != nil || sd == nil {
		r.tb.Fatalf("font without ToUnicode map (err %v)", err)
	}
	if err := sd.DecodeWithLimit(maxDecoded); err != nil {
		r.tb.Fatalf("decoding ToUnicode: %v", err)
	}
	m := parseToUnicode(r.tb, sd.Content)
	if ir, ok := ref.(types.IndirectRef); ok {
		r.cmaps[ir] = m
	}
	return m
}

var (
	bfchar  = regexp.MustCompile(`<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]+)>`)
	bfrange = regexp.MustCompile(`<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]+)>`)
)

func parseToUnicode(tb testing.TB, cmap []byte) map[uint16]string {
	tb.Helper()
	out := map[uint16]string{}
	s := string(cmap)
	for {
		i := strings.Index(s, "beginbfchar")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "endbfchar")
		if j < 0 {
			break
		}
		for _, m := range bfchar.FindAllStringSubmatch(s[i:i+j], -1) {
			g, err := strconv.ParseUint(m[1], 16, 16)
			if err != nil {
				tb.Fatalf("bad glyph id %q: %v", m[1], err)
			}
			out[uint16(g)] = utf16Hex(tb, m[2])
		}
		s = s[i+j:]
	}
	s = string(cmap)
	for {
		i := strings.Index(s, "beginbfrange")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "endbfrange")
		if j < 0 {
			break
		}
		for _, m := range bfrange.FindAllStringSubmatch(s[i:i+j], -1) {
			lo, err := strconv.ParseInt(m[1], 16, 32)
			hi, err2 := strconv.ParseInt(m[2], 16, 32)
			if err != nil || err2 != nil {
				tb.Fatalf("bad bfrange %q: %v %v", m[0], err, err2)
			}
			base := []rune(utf16Hex(tb, m[3]))
			if len(base) != 1 {
				continue
			}
			for g := lo; g <= hi && g <= 0xffff; g++ {
				out[uint16(g&0xffff)] = string(base[0] + rune(min(g-lo, 0xffff)&0xffff))
			}
		}
		s = s[i+j:]
	}
	return out
}

func utf16Hex(tb testing.TB, h string) string {
	tb.Helper()
	var units []uint16
	for i := 0; i+4 <= len(h); i += 4 {
		u, err := strconv.ParseUint(h[i:i+4], 16, 16)
		if err != nil {
			tb.Fatalf("bad UTF-16 unit in %q: %v", h, err)
		}
		units = append(units, uint16(u))
	}
	return string(utf16.Decode(units))
}

// decodeGlyphs reads 2-byte glyph ids (Identity-H).
func decodeGlyphs(s string, cmap map[uint16]string) string {
	var b strings.Builder
	for i := 0; i+1 < len(s); i += 2 {
		b.WriteString(cmap[uint16(s[i])<<8|uint16(s[i+1])])
	}
	return b.String()
}

type tokenKind int

const (
	tokOp tokenKind = iota
	tokString
	tokName
	tokOther
)

type token struct {
	kind tokenKind
	val  string
}

// tokenize splits a content stream into operators, strings (hex or literal,
// arrays flattened) and other operands; enough for text operators.
func tokenize(tb testing.TB, b []byte) []token {
	tb.Helper()
	var out []token
	isSpace := func(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == 0 || c == '\f' }
	isDelim := func(c byte) bool { return strings.IndexByte("()<>[]{}/%", c) >= 0 }
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case isSpace(c):
			i++
		case c == '%':
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
		case c == '[' || c == ']':
			i++
		case c == '<' && i+1 < len(b) && b[i+1] == '<':
			i += 2
		case c == '>' && i+1 < len(b) && b[i+1] == '>':
			i += 2
		case c == '<':
			j := bytes.IndexByte(b[i:], '>')
			if j < 0 {
				return out
			}
			h := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
					return -1
				}
				return r
			}, string(b[i+1:i+j]))
			if len(h)%2 == 1 {
				h += "0"
			}
			raw := make([]byte, 0, len(h)/2)
			for k := 0; k+2 <= len(h); k += 2 {
				v, err := strconv.ParseUint(h[k:k+2], 16, 8)
				if err != nil {
					tb.Fatalf("bad hex string in a content stream: %v", err)
				}
				raw = append(raw, byte(v))
			}
			out = append(out, token{tokString, string(raw)})
			i += j + 1
		case c == '(':
			var raw []byte
			depth := 1
			i++
			for i < len(b) && depth > 0 {
				switch ch := b[i]; {
				case ch == '\\' && i+1 < len(b):
					i++
					switch e := b[i]; e {
					case 'n':
						raw = append(raw, '\n')
					case 'r':
						raw = append(raw, '\r')
					case 't':
						raw = append(raw, '\t')
					case 'b':
						raw = append(raw, '\b')
					case 'f':
						raw = append(raw, '\f')
					case '0', '1', '2', '3', '4', '5', '6', '7':
						v, n := 0, 0
						for n < 3 && i < len(b) && b[i] >= '0' && b[i] <= '7' {
							v = v*8 + int(b[i]-'0')
							i++
							n++
						}
						i--
						raw = append(raw, byte(v))
					default:
						raw = append(raw, e)
					}
				case ch == '(':
					depth++
					raw = append(raw, ch)
				case ch == ')':
					depth--
					if depth > 0 {
						raw = append(raw, ch)
					}
				default:
					raw = append(raw, ch)
				}
				i++
			}
			out = append(out, token{tokString, string(raw)})
		case c == '/':
			j := i + 1
			for j < len(b) && !isSpace(b[j]) && !isDelim(b[j]) {
				j++
			}
			out = append(out, token{tokName, string(b[i+1 : j])})
			i = j
		default:
			j := i
			for j < len(b) && !isSpace(b[j]) && !isDelim(b[j]) {
				j++
			}
			if j == i {
				i++
				continue
			}
			w := string(b[i:j])
			if _, err := strconv.ParseFloat(w, 64); err == nil || w == "true" || w == "false" || w == "null" {
				out = append(out, token{tokOther, w})
			} else {
				out = append(out, token{tokOp, w})
			}
			i = j
		}
	}
	return out
}

// pageNumberFooter matches "Page i of n" with the spaces possibly lost.
func pageNumberFooter(i, n int) *regexp.Regexp {
	return regexp.MustCompile(`Page\s*` + strconv.Itoa(i) + `\s*of\s*` + strconv.Itoa(n) + `(\D|$)`)
}

func TestPDFPageTexts_readsTheTextOfEachPage(t *testing.T) {
	if got := tokenize(t, []byte(`BT /F1 10 Tf [<0001> -20 (a\)b)] TJ ET`)); len(got) != 9 {
		t.Fatalf("tokens = %+v", got)
	}
	m := parseToUnicode(t, []byte("1 beginbfchar\n<0001> <0041>\nendbfchar\n1 beginbfrange\n<0010> <0012> <0061>\nendbfrange\n"))
	if got := decodeGlyphs("\x00\x01\x00\x10\x00\x12", m); got != "Aac" {
		t.Errorf("decodeGlyphs = %q, want Aac", got)
	}
}
