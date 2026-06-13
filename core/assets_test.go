package core

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func writeTempAsset(t *testing.T, data []byte) *os.File {
	t.Helper()

	path := filepath.Join(t.TempDir(), "asset.uasset")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		file.Close()
	})
	return file
}

func emptyFF7R2Uexp(headSize int) []byte {
	buf := &bytes.Buffer{}
	buf.Write(bytes.Repeat([]byte{0xAB}, headSize))
	binary.Write(buf, binary.LittleEndian, int32(3))
	buf.Write([]byte{'U', 'S', 0})
	buf.Write(make([]byte, 8))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func shortEmptyFF7R2Uexp(headSize int) []byte {
	buf := &bytes.Buffer{}
	buf.Write(bytes.Repeat([]byte{0xAB}, headSize))
	binary.Write(buf, binary.LittleEndian, int32(3))
	buf.Write([]byte{'J', 'P', 0})
	buf.Write(make([]byte, 4))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func noNullFF7R2Uexp(headSize int) []byte {
	buf := &bytes.Buffer{}
	buf.Write(bytes.Repeat([]byte{0xAB}, headSize))
	binary.Write(buf, binary.LittleEndian, int32(3))
	buf.Write([]byte{'J', 'P', 0})
	buf.Write(make([]byte, 4))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, int32(9))
	buf.Write([]byte("$TEST_ID\x00"))
	binary.Write(buf, binary.LittleEndian, int32(6))
	buf.Write([]byte("hello\x00"))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func TestUexpReadDetectsVariableFF7R2HeadSize(t *testing.T) {
	const headSize = 29
	file := writeTempAsset(t, emptyFF7R2Uexp(headSize))

	s := NewSerializer()
	s.SetReadFile(file)
	s.SetVersion(VER_FF7R2)

	uexp := &Uexp{}
	uexp.Read(s)

	if len(uexp.head) != headSize {
		t.Fatalf("head size = %d, want %d", len(uexp.head), headSize)
	}
	if uexp.Lang != "US" {
		t.Fatalf("language = %q, want US", uexp.Lang)
	}
	if len(uexp.Entries) != 0 {
		t.Fatalf("entry count = %d, want 0", len(uexp.Entries))
	}
}

func TestUexpReadSupportsShortEmptyFF7R2Asset(t *testing.T) {
	const headSize = 2
	file := writeTempAsset(t, shortEmptyFF7R2Uexp(headSize))

	s := NewSerializer()
	s.SetReadFile(file)
	s.SetVersion(VER_FF7R2)

	uexp := &Uexp{}
	uexp.Read(s)

	if len(uexp.head) != headSize {
		t.Fatalf("head size = %d, want %d", len(uexp.head), headSize)
	}
	if uexp.Lang != "JP" {
		t.Fatalf("language = %q, want JP", uexp.Lang)
	}
	if !uexp.hasEntryHeader {
		t.Fatal("hasEntryHeader = false, want true")
	}
	if uexp.hasEntryNull {
		t.Fatal("hasEntryNull = true, want false")
	}
	if len(uexp.noneId) != 4 {
		t.Fatalf("noneId size = %d, want 4", len(uexp.noneId))
	}
	if len(uexp.Entries) != 0 {
		t.Fatalf("entry count = %d, want 0", len(uexp.Entries))
	}
}

func TestUexpReadSupportsFF7R2EntryCountWithoutNull(t *testing.T) {
	const headSize = 2
	file := writeTempAsset(t, noNullFF7R2Uexp(headSize))

	s := NewSerializer()
	s.SetReadFile(file)
	s.SetVersion(VER_FF7R2)

	uexp := &Uexp{}
	uexp.Read(s)

	if len(uexp.head) != headSize {
		t.Fatalf("head size = %d, want %d", len(uexp.head), headSize)
	}
	if uexp.hasEntryNull {
		t.Fatal("hasEntryNull = true, want false")
	}
	if len(uexp.noneId) != 4 {
		t.Fatalf("noneId size = %d, want 4", len(uexp.noneId))
	}
	if uexp.rawEntryIds {
		t.Fatal("rawEntryIds = true, want false")
	}
	if len(uexp.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(uexp.Entries))
	}
	if uexp.Entries[0].Id != "$TEST_ID" {
		t.Fatalf("entry id = %q, want $TEST_ID", uexp.Entries[0].Id)
	}
	if uexp.Entries[0].Text != "hello" {
		t.Fatalf("entry text = %q, want hello", uexp.Entries[0].Text)
	}
}

func TestUassetReadDetectsShiftedFF7R2UexpStart(t *testing.T) {
	const (
		expectedUexpStart = 96
		actualUexpStart   = 104
		headSize          = 29
	)

	summary := make([]byte, 60)
	binary.LittleEndian.PutUint32(summary[24:], 60)                   // NameMapOffset
	binary.LittleEndian.PutUint32(summary[52:], 80)                   // GraphDataOffset
	binary.LittleEndian.PutUint32(summary[56:], expectedUexpStart-80) // GraphDataSize

	data := append([]byte{}, summary...)
	data = append(data, bytes.Repeat([]byte{0xCD}, actualUexpStart-len(data))...)
	data = append(data, emptyFF7R2Uexp(headSize)...)

	file := writeTempAsset(t, data)
	serializer := NewSerializer()
	serializer.SetReadFile(file)

	uasset := &Uasset{}
	uasset.Read(serializer)

	uexp := &Uexp{}
	uexp.Read(serializer)
	prefixSize := len(uasset.rawBin) + len(uexp.head)
	if prefixSize != actualUexpStart+headSize {
		t.Fatalf("preserved prefix size = %d, want %d", prefixSize, actualUexpStart+headSize)
	}
}
