package core

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"
)

var LANG_LIST = []string{
	"BR", "CN", "DE", "ES",
	"FR", "IT", "JP", "KR",
	"MX", "TW", "US",
}

type Uexp struct {
	head           []byte
	Lang           string  `json:"language"`
	noneId         []byte  // name map id for "None"
	hasEntryHeader bool    // FF7R2 empty assets can end before the null/count fields.
	hasEntryNull   bool    // FF7R2 1.005 assets can omit the null before entry count.
	rawEntryIds    bool    // FF7R2 1.005 no-null entries use null-terminated ids.
	Entries        []Entry `json:"entries,omitempty"`
}

type ZenPackageSummary struct {
	NameId                    uint32
	NameNumber                uint32
	SourceNameId              uint32
	SourceNameNumber          uint32
	PkgFlags                  uint32
	CookedHeaderSize          uint32
	NameMapOffset             int32
	NameMapSize               int32
	NameHashesOffset          int32
	NameHashesSize            int32
	ImportOffset              int32
	ExportOffset              int32
	ExportBundleEntriesOffset int32
	GraphDataOffset           int32
	GraphDataSize             int32
}

func (s *ZenPackageSummary) GetNameMapEndOffset() int {
	return int(s.NameMapOffset + s.NameMapSize)
}

func (s *ZenPackageSummary) GetUassetEndOffset() int {
	return int(s.GraphDataOffset + s.GraphDataSize)
}

func isKnownLang(lang string) bool {
	return slices.Contains(LANG_LIST, lang)
}

func readUint32At(s *Serializer, offset int) (uint32, bool) {
	if offset < 0 || offset+4 > s.endOffset {
		return 0, false
	}
	oldOffset := s.GetOffset()
	s.Seek(offset, 0)
	buf := s.Read(4)
	s.Seek(oldOffset, 0)
	return s.order.Uint32(buf), true
}

func readFF7R2LangAt(s *Serializer, offset int) (string, int, bool) {
	strlen, ok := readUint32At(s, offset)
	if !ok || strlen != 3 {
		return "", offset, false
	}

	valueOffset := offset + 4
	if valueOffset+int(strlen) > s.endOffset {
		return "", offset, false
	}

	oldOffset := s.GetOffset()
	s.Seek(valueOffset, 0)
	buf := s.Read(int(strlen))
	s.Seek(oldOffset, 0)

	if len(buf) != 3 || buf[2] != 0 {
		return "", offset, false
	}

	lang := string(buf[:2])
	return lang, valueOffset + int(strlen), isKnownLang(lang)
}

func findFF7R2UexpHeadSize(s *Serializer, uexpStart int) (int, bool) {
	for headSize := 0; headSize <= ff7r2MaxUexpHeadSize; headSize++ {
		lang, nextOffset, ok := readFF7R2LangAt(s, uexpStart+headSize)
		if !ok || !isKnownLang(lang) {
			continue
		}

		countOffset := nextOffset + 4 // FF7R2 1.005 uses a 4-byte name id for "None".
		entryCount, ok := readUint32At(s, countOffset)
		if ok && entryCount < 65536 && (entryCount > 0 || countOffset+4 == s.endOffset) {
			return headSize, true
		}

		nullOffset := nextOffset + 8 // Skip the name map id for "None".
		if nullOffset == s.endOffset {
			return headSize, true
		}
		nullValue, ok := readUint32At(s, nullOffset)
		if !ok {
			continue
		}
		if nullValue != 0 {
			if nullValue < 65536 {
				return headSize, true
			}
			continue
		}

		entryCount, ok = readUint32At(s, nullOffset+4)
		if !ok || entryCount >= 65536 {
			continue
		}
		return headSize, true
	}
	return 0, false
}

func findFF7R2UexpStart(s *Serializer, expectedOffset int) (int, bool) {
	if _, ok := findFF7R2UexpHeadSize(s, expectedOffset); ok {
		return expectedOffset, true
	}

	back := min(ff7r2UexpStartScanBack, expectedOffset)
	ahead := min(ff7r2UexpStartScanAhead, s.endOffset-expectedOffset)
	maxDistance := max(back, ahead)

	for distance := 1; distance <= maxDistance; distance++ {
		if distance <= back {
			offset := expectedOffset - distance
			if _, ok := findFF7R2UexpHeadSize(s, offset); ok {
				return offset, true
			}
		}
		if distance <= ahead {
			offset := expectedOffset + distance
			if _, ok := findFF7R2UexpHeadSize(s, offset); ok {
				return offset, true
			}
		}
	}
	return expectedOffset, false
}

type Uasset struct {
	Names   []string
	rawBin  []byte
	Uexp    *Uexp
	Ver     VersionEnum
	Summary *ZenPackageSummary
}

var HEAD_MAGIC = []byte{0x00, 0x03}
var UNREAL_SIGNATURE = []byte{0xC1, 0x83, 0x2A, 0x9E}

const (
	ff7r2DefaultUexpHeadSize = 25
	ff7r2MaxUexpHeadSize     = 128
	ff7r2UexpStartScanBack   = 1024
	ff7r2UexpStartScanAhead  = 65536
)

func (uexp *Uexp) Read(s *Serializer) {
	uexp.hasEntryHeader = true
	uexp.hasEntryNull = true
	uexp.rawEntryIds = false
	if s.Ver == VER_FF7R {
		uexp.head = s.Read(2)
	} else if s.Ver >= VER_FF7R2 {
		headSize := ff7r2DefaultUexpHeadSize
		if detectedHeadSize, ok := findFF7R2UexpHeadSize(s, s.GetOffset()); ok {
			headSize = detectedHeadSize
		}
		uexp.head = s.Read(headSize)
	}

	uexp.Lang = s.ReadString()

	if !isKnownLang(uexp.Lang) {
		Throw(fmt.Errorf("unknown language detected. (%s)", uexp.Lang))
	}

	var entryCount uint32
	if s.Ver != VER_FF7R {
		noneOffset := s.GetOffset()
		if count, ok := readUint32At(s, noneOffset+4); ok &&
			count < 65536 &&
			(count > 0 || noneOffset+8 == s.endOffset) {
			uexp.noneId = s.Read(4)
			uexp.hasEntryNull = false
			entryCount = s.ReadUint32()
		} else {
			uexp.noneId = s.Read(8)
			if s.GetOffset() == s.endOffset {
				uexp.hasEntryHeader = false
				uexp.Entries = []Entry{}
				return
			}
			value, ok := readUint32At(s, s.GetOffset())
			if !ok {
				Throw("EOF")
			}
			if value == 0 {
				uexp.hasEntryNull = true
				s.ReadNull()
				entryCount = s.ReadUint32()
			} else {
				uexp.hasEntryNull = false
				uexp.rawEntryIds = true
				entryCount = s.ReadUint32()
			}
		}
	} else {
		s.ReadNull()
		entryCount = s.ReadUint32()
	}
	if entryCount >= 65536 {
		Throw(fmt.Errorf("unexpected entry count: %d", entryCount))
	}
	uexp.Entries = make([]Entry, 0, entryCount)
	for range entryCount {
		e := Entry{}
		e.ReadWithOptions(s, uexp.rawEntryIds)
		uexp.Entries = append(uexp.Entries, e)
	}

	if s.Ver != VER_FF7R {
		return
	}

	signature := s.Read(4)
	if !bytes.Equal(signature, UNREAL_SIGNATURE) {
		Throw(fmt.Errorf("unexpected signature: %v", signature))
	}
}

func (uexp *Uexp) Write(s *Serializer) {
	s.Write(uexp.head)
	s.WriteString(uexp.Lang)
	if s.Ver != VER_FF7R {
		s.Write(uexp.noneId)
	}
	if s.Ver != VER_FF7R && !uexp.hasEntryHeader {
		return
	}
	if uexp.hasEntryNull {
		s.WriteNull()
	}
	entryCount := len(uexp.Entries)
	s.WriteUint32(uint32(entryCount))
	for i := range entryCount {
		uexp.Entries[i].WriteWithOptions(s, uexp.rawEntryIds)
	}

	if s.Ver == VER_FF7R {
		s.Write(UNREAL_SIGNATURE)
	}
}

func (uexp *Uexp) GetBinSize() int {
	size := len(uexp.head) + len(uexp.noneId)
	size += GetStringBinSize(uexp.Lang)
	if uexp.hasEntryHeader {
		size += 4
		if uexp.hasEntryNull {
			size += 4
		}
	}
	for i := range len(uexp.Entries) {
		size += uexp.Entries[i].GetBinSizeWithOptions(uexp.rawEntryIds)
	}
	return size
}

func (uexp *Uexp) NameIdToString(uasset *Uasset) {
	for i := range len(uexp.Entries) {
		uexp.Entries[i].NameIdToString(uasset)
	}
}

func (uexp *Uexp) UpdateNameId(uasset *Uasset) {
	for i := range len(uexp.Entries) {
		uexp.Entries[i].UpdateNameId(uasset)
	}
}

func (uexp *Uexp) FindEntry(key string, firstId int) int {
	// Entries are sorted in alphabetical order.
	// So, we can do the binary search to find a key.

	left, right := 0, len(uexp.Entries)-1
	if firstId < left || right < firstId {
		return -1 // Invalid firstId
	}

	mid := firstId
	for left <= right {
		comp := strings.Compare(key, uexp.Entries[mid].Id)

		if comp == 0 {
			return mid // Found
		} else if comp < 0 {
			right = mid - 1
		} else {
			left = mid + 1
		}
		mid = (left + right) / 2
	}
	return -1 // Not found
}

func (uexp *Uexp) UpdateWithNewUexp(newUexp *Uexp) {
	if !slices.Contains(LANG_LIST, newUexp.Lang) {
		Throw(fmt.Errorf("unknown language detected. (%s)", newUexp.Lang))
	}
	uexp.Lang = newUexp.Lang
	for i := range len(newUexp.Entries) {
		e := newUexp.Entries[i]
		id := uexp.FindEntry(e.Id, min(i, len(newUexp.Entries)))
		if id < 0 {
			Throw(fmt.Errorf("unknown entry detected. (%s)", e.Id))
		}
		uexp.Entries[id].UpdateWithNewEntry(&e)
	}
}

func (uexp *Uexp) Print(verbose ...bool) {
	fmt.Printf("lang: %s\n", uexp.Lang)
	entryCount := len(uexp.Entries)
	fmt.Printf("entry count: %d\n", entryCount)
	if len(verbose) == 0 || !verbose[0] {
		return
	}
	if entryCount > 0 {
		fmt.Println("entries:")
	}
	for i := range len(uexp.Entries) {
		uexp.Entries[i].Print()
	}
}

func (uexp *Uexp) ReadFromCsv(r *csv.Reader) {
	last_id := 0
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			Throw(err)
		} else if len(row) != 3 {
			Throw("each row should has 3 items in csv")
		}
		id := TrimUTF8BOM(row[0])
		if id == "id" {
			continue // first row
		} else if id == "language" {
			lang := row[2]
			if !slices.Contains(LANG_LIST, lang) {
				Throw(fmt.Errorf("unknown language detected. (%s)", lang))
			}
			uexp.Lang = lang
			continue
		}
		i := uexp.FindEntry(id, last_id)
		if i < 0 {
			Throw(fmt.Errorf("unknown entry detected. (%s)", id))
		}
		last_id = i
		uexp.Entries[i].UpdateWithCsv(row)
	}
}

func (uexp *Uexp) WriteAsCsv(w *csv.Writer) {
	record := []string{"id", "sub_id", "text"}
	if err := w.Write(record); err != nil {
		Throw(err)
	}
	record = []string{"language", "", uexp.Lang}
	if err := w.Write(record); err != nil {
		Throw(err)
	}
	for i := range len(uexp.Entries) {
		uexp.Entries[i].WriteAsCsv(w)
	}
}

func (uasset *Uasset) Read(s *Serializer) {
	// Make sure it has fourCC for uasset
	signature := s.Read(4)
	if bytes.Equal(signature, UNREAL_SIGNATURE) {
		uasset.Ver = VER_FF7R
		s.SetVersion(uasset.Ver)

		// We just read a name map, don't parse the whole binary.
		s.Seek(41, 0)
		nameCount := s.ReadUint32()
		if nameCount >= 2048 {
			Throw(fmt.Errorf("unexpected name count: %d", nameCount))
		}
		s.Seek(193, 0)
		uasset.Names = make([]string, 0, nameCount)
		for range nameCount {
			name := s.ReadString()
			uasset.Names = append(uasset.Names, name)
			s.Seek(4, 1) // skip hash
		}

		wholeSize := s.GetFileSize()
		s.Seek(0, 0)
		uasset.rawBin = s.Read(wholeSize)
	} else if bytes.Equal(signature, []byte{0, 0, 0, 0}) {
		uasset.Ver = VER_FF7R2
		s.SetVersion(uasset.Ver)

		s.Seek(0, 0)
		uasset.Summary = &ZenPackageSummary{}
		s.ReadStruct(uasset.Summary)
		s.Seek(int(uasset.Summary.NameMapOffset), 0)
		uasset.Names = make([]string, 0, 16)
		namesEndOffset := uasset.Summary.GetNameMapEndOffset()
		for s.GetOffset() < namesEndOffset {
			name := s.ReadZenString()
			uasset.Names = append(uasset.Names, name)
		}
		uassetEndOffset := uasset.Summary.GetUassetEndOffset()
		uexpStartOffset, _ := findFF7R2UexpStart(s, uassetEndOffset)
		if uexpStartOffset < 0 || uexpStartOffset > s.endOffset {
			Throw(fmt.Errorf("unexpected uasset end offset: %d", uexpStartOffset))
		}
		s.Seek(0, 0)
		uasset.rawBin = s.Read(uexpStartOffset)

	} else {
		Throw(fmt.Errorf("unexpected fourCC: %v", signature))
	}
}

func (uasset *Uasset) Write(s *Serializer) {
	// Make sure it has fourCC for uasset
	s.Write(uasset.rawBin)

	if uasset.Ver == VER_FF7R {
		s.Seek(-92, 2)
		uexpSize := int32(uasset.Uexp.GetBinSize())
		s.WriteInt32(uexpSize)
	} else {
		s.Seek(int(uasset.Summary.ExportOffset+8), 0)
		uexpSize := int32(uasset.Uexp.GetBinSize())
		s.WriteInt32(uexpSize)
		s.Seek(len(uasset.rawBin), 0)
	}
}

func (uasset *Uasset) Update() {
	uasset.Uexp.UpdateNameId(uasset)
}

func (uasset *Uasset) Print(verbose ...bool) {
	nameCount := len(uasset.Names)
	fmt.Printf("name count: %d\n", nameCount)
	if len(verbose) != 0 && verbose[0] {
		for i := range len(uasset.Names) {
			fmt.Printf("  %s\n", uasset.Names[i])
		}
	}
	uasset.Uexp.Print(verbose[0])
}

func (uasset *Uasset) ReadFromFile(filePath string) {
	uexp := &Uexp{}

	serializer := NewSerializer()

	// Open a read only file
	fmt.Printf("Reading %s...\n", filePath)
	uassetFile := OpenFile(filePath)
	defer uassetFile.Close()

	serializer.SetReadFile(uassetFile)
	uasset.Read(serializer)

	if uasset.Ver == VER_FF7R {
		// Read .uexp
		uexpPath := RemoveExtension(filePath) + ".uexp"
		fmt.Printf("Reading %s...\n", uexpPath)
		uexpFile := OpenFile(uexpPath)
		defer uexpFile.Close()
		serializer.SetReadFile(uexpFile)
	}

	uexp.Read(serializer)
	uexp.NameIdToString(uasset)
	uasset.Uexp = uexp
}

func (uasset *Uasset) WriteToFile(filePath string) {
	uasset.Update()

	serializer := NewSerializer()

	// Open or create a file
	fmt.Printf("Writing %s...\n", filePath)
	uassetFile := CreateFile(filePath)
	defer uassetFile.Close()

	serializer.SetWriteFile(uassetFile)
	serializer.SetVersion(uasset.Ver)
	uasset.Write(serializer)

	if uasset.Ver == VER_FF7R {
		// Read .uexp
		uexpPath := RemoveExtension(filePath) + ".uexp"
		fmt.Printf("Writing %s...\n", uexpPath)
		uexpFile := CreateFile(uexpPath)
		defer uexpFile.Close()
		serializer.SetWriteFile(uexpFile)
	}

	uasset.Uexp.Write(serializer)
}
