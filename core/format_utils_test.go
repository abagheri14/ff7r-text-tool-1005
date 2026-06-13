package core

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
)

func TestLoadFromJsonAllowsUTF8BOM(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"language":"US"}`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	uexp := &Uexp{}
	LoadFromJson(path, uexp)
	if uexp.Lang != "US" {
		t.Fatalf("Lang = %q, want US", uexp.Lang)
	}
}

func TestReadFromCsvAllowsUTF8BOMHeader(t *testing.T) {
	uexp := &Uexp{Lang: "US"}
	reader := csv.NewReader(strings.NewReader(string([]byte{0xEF, 0xBB, 0xBF}) + "id,sub_id,text\nlanguage,,US\n"))

	uexp.ReadFromCsv(reader)
	if uexp.Lang != "US" {
		t.Fatalf("Lang = %q, want US", uexp.Lang)
	}
}
