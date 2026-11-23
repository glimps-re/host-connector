//go:build linux

package main

import (
	"bytes"
	"context"
	"hash/crc32"
	"slices"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"

	le "encoding/binary"
)

// rawEntry is an entry of a zip written byte by byte, with a local header and a
// central entry that may disagree: that is what the walk of the headers is for.
type rawEntry struct {
	name   string
	method uint16
	flags  uint16
	// data follows the local header, then the descriptor, then slack.
	data []byte
	// local and central sizes, as written (saturated ones need the zip64 flags).
	localComp, localUncomp     uint64
	centralComp, centralUncomp uint64
	attrs                      uint32
	madeBy                     uint16
	crc                        uint32
	zip64Local, zip64Central   bool
	// descriptor is the form of the data descriptor after the data: 0 none, 1 of
	// 12 bytes, 2 of 16 (signed), 3 of 20 (ZIP64), 4 of 24 (ZIP64, signed). Its
	// fields are the ones of the central entry.
	descriptor int
	// badDescriptor writes a descriptor that is not the one of the directory.
	badDescriptor bool
	// slack is written after the entry: a record the directory does not list.
	slack []byte
	// sameOffsetAs, when above 0, is the 1-based index of an earlier entry whose
	// local offset the central entry gives.
	sameOffsetAs int
	// localExtra is the extra field of the local header, after the ZIP64 field;
	// extraBefore is put in front of it.
	localExtra  []byte
	extraBefore []byte
	// unlisted writes the local record and no central entry.
	unlisted bool
	// centralName, when not empty, is the name the central entry gives.
	centralName string
	// centralMethod, when not nil, is the method the central entry gives.
	centralMethod *uint16
	// centralOnly writes the central entry and no local record (its offset is the
	// one of sameOffsetAs).
	centralOnly bool
}

// rawZip is a zip built from entries.
type rawZip struct {
	entries        []rawEntry
	zip64Directory bool
	comment        string
	// prefix is written before the first entry, whose offsets include it (a
	// self-extracting stub).
	prefix []byte
	// permuteCentral writes the central entries in another order than the local
	// records (the size of the zip must not be a multiple of 7919).
	permuteCentral bool
	// trailing is written after the end of directory.
	trailing []byte
	// decoy puts, in the comment of the end of directory, a copy of the directory
	// and an end of directory that leads to it.
	decoy bool
	// signingBlock puts an APK Signing Block between the last entry and the
	// directory.
	signingBlock bool
}

// deflateEmptyData is a deflate stream of one final empty block.
var deflateEmptyData = []byte{0x03, 0x00}

func put16(b []byte, v uint16) []byte { return le.LittleEndian.AppendUint16(b, v) }
func put32(b []byte, v uint32) []byte { return le.LittleEndian.AppendUint32(b, v) }
func put64(b []byte, v uint64) []byte { return le.LittleEndian.AppendUint64(b, v) }

func u16(n int) uint16 { return uint16(n & 0xFFFF) }

func u32(v uint64) uint32 { return uint32(v & 0xFFFFFFFF) }

func zip64Extra(vals ...uint64) []byte {
	extra := put16(nil, 1)
	extra = put16(extra, u16(8*len(vals)))
	for _, v := range vals {
		extra = put64(extra, v)
	}
	return extra
}

func fileEntry(name, content string) rawEntry {
	n := uint64(len(content))
	return rawEntry{name: name, data: []byte(content), localComp: n, localUncomp: n, centralComp: n, centralUncomp: n, crc: crc32.ChecksumIEEE([]byte(content))}
}

func folderEntry(name string) rawEntry { return rawEntry{name: name} }

// jarFolder is a folder as the jar tool writes it: deflated, with a data
// descriptor, and no size in the local header.
func jarFolder(name string) rawEntry {
	return rawEntry{name: name, method: zipMethodDeflate, data: deflateEmptyData, centralComp: 2, descriptor: 2}
}

func (z rawZip) bytes(t testing.TB) []byte {
	t.Helper()
	out := slices.Clone(z.prefix)
	var dir []byte
	offsets := make([]uint64, 0, len(z.entries))
	for _, e := range z.entries {
		offset := uint64(len(out))
		offsets = append(offsets, offset)
		if e.centralOnly {
			continue
		}
		if e.descriptor > 0 {
			e.flags |= zipFlagDescriptor
		}
		localExtra := e.localExtra
		lc, lu := u32(e.localComp), u32(e.localUncomp)
		if e.zip64Local {
			lc, lu = zipSaturated32, zipSaturated32
			localExtra = append(append(slices.Clone(e.extraBefore), zip64Extra(e.localUncomp, e.localComp)...), localExtra...)
		}
		out = put32(out, zipLocalSignature)
		out = put16(out, 20)
		out = put16(out, e.flags)
		out = put16(out, e.method)
		out = put32(out, 0)
		out = put32(out, e.crc)
		out = put32(out, lc)
		out = put32(out, lu)
		out = put16(out, u16(len(e.name)))
		out = put16(out, u16(len(localExtra)))
		out = append(out, e.name...)
		out = append(out, localExtra...)
		out = append(out, e.data...)
		descriptorCRC := e.crc
		if e.badDescriptor {
			descriptorCRC ^= 1
		}
		switch e.descriptor {
		case 1, 2:
			if e.descriptor == 2 {
				out = put32(out, zipDescriptorSignature)
			}
			out = put32(out, descriptorCRC)
			out = put32(out, u32(e.centralComp))
			out = put32(out, u32(e.centralUncomp))
		case 3, 4:
			if e.descriptor == 4 {
				out = put32(out, zipDescriptorSignature)
			}
			out = put32(out, descriptorCRC)
			out = put64(out, e.centralComp)
			out = put64(out, e.centralUncomp)
		}
		out = append(out, e.slack...)
	}
	if z.signingBlock {
		pairs := put64(nil, 8)
		pairs = put32(pairs, 0x7109871a)
		pairs = put32(pairs, 1)
		size := uint64(len(pairs)) + 24
		out = put64(out, size)
		out = append(out, pairs...)
		out = put64(out, size)
		out = append(out, zipSigBlockMagic...)
	}
	cdOff := uint64(len(out))
	dirEntries := make([][]byte, 0, len(z.entries))
	for i, e := range z.entries {
		if e.unlisted {
			continue
		}
		start := len(dir)
		if e.descriptor > 0 {
			e.flags |= zipFlagDescriptor
		}
		co := offsets[i]
		if e.sameOffsetAs > 0 {
			co = offsets[e.sameOffsetAs-1]
		}
		cc, cu, offset32 := u32(e.centralComp), u32(e.centralUncomp), u32(co)
		var centralExtra []byte
		if e.zip64Central {
			centralExtra = zip64Extra(e.centralUncomp, e.centralComp, co)
			cc, cu, offset32 = zipSaturated32, zipSaturated32, zipSaturated32
		}
		dir = put32(dir, zipCentralSignature)
		dir = put16(dir, e.madeBy)
		dir = put16(dir, 20)
		dir = put16(dir, e.flags)
		method := e.method
		if e.centralMethod != nil {
			method = *e.centralMethod
		}
		dir = put16(dir, method)
		dir = put32(dir, 0)
		dir = put32(dir, e.crc)
		dir = put32(dir, cc)
		dir = put32(dir, cu)
		centralName := e.name
		if e.centralName != "" {
			centralName = e.centralName
		}
		dir = put16(dir, u16(len(centralName)))
		dir = put16(dir, u16(len(centralExtra)))
		dir = put16(dir, 0)
		dir = put16(dir, 0)
		dir = put16(dir, 0)
		dir = put32(dir, e.attrs)
		dir = put32(dir, offset32)
		dir = append(dir, centralName...)
		dir = append(dir, centralExtra...)
		dirEntries = append(dirEntries, dir[start:])
	}
	if z.permuteCentral {
		permuted := make([]byte, 0, len(dir))
		for i := range dirEntries {
			permuted = append(permuted, dirEntries[(i*7919)%len(dirEntries)]...)
		}
		dir = permuted
	}
	out = append(out, dir...)
	n := len(dirEntries)
	if z.decoy {
		decoyAt := u32(uint64(len(out) + zipEOCDLen))
		comment := string(dir) + string(eocd(nil, u16(n), u32(uint64(len(dir))), decoyAt, ""))
		return append(eocd(out, u16(n), u32(uint64(len(dir))), u32(cdOff), comment), z.trailing...)
	}
	if z.zip64Directory {
		recOff := uint64(len(out))
		out = put32(out, zip64EOCDSignature)
		out = put64(out, 44)
		out = put16(out, 45)
		out = put16(out, 45)
		out = put32(out, 0)
		out = put32(out, 0)
		out = put64(out, uint64(n))
		out = put64(out, uint64(n))
		out = put64(out, uint64(len(dir)))
		out = put64(out, cdOff)
		out = put32(out, zip64LocatorSignature)
		out = put32(out, 0)
		out = put64(out, recOff)
		out = put32(out, 1)
		return eocd(out, zipSaturated16, zipSaturated32, zipSaturated32, z.comment)
	}
	return append(eocd(out, u16(n), u32(uint64(len(dir))), u32(cdOff), z.comment), z.trailing...)
}

func eocd(out []byte, n uint16, cdSize, cdOff uint32, comment string) []byte {
	out = put32(out, zipEOCDSignature)
	out = put16(out, 0)
	out = put16(out, 0)
	out = put16(out, n)
	out = put16(out, n)
	out = put32(out, cdSize)
	out = put32(out, cdOff)
	out = put16(out, u16(len(comment)))
	return append(out, comment...)
}

// walkBytes walks a zip of entries entries, among which folders folders, as 7-Zip
// would have listed them.
func walkBytes(b []byte, entries, folders int) error {
	_, err := walkZip(context.Background(), bytes.NewReader(b), int64(len(b)), entries, folders)
	return err
}

const dosFolder = 0x10

var (
	extractionMode = plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100000, MaxTotalSize: 1 << 30}
	checkOnlyMode  = plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100000, MaxTotalSize: 1 << 30, CheckOnly: true}
)
