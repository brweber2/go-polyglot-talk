// dumpdns - utility for printing the contents of binary nsd.db file
//
// Description:
//
// This program prints wire format DNS records stored in NSD db file format v7
// (NSDdbV07).  It can additionally print some additional debug information
// about the file contents if the -d flag is specified.
//
// Note that this does not always print out human readable text format.  Some
// resource record types do not pretty print and will dump the relevant bytes.
//
// Note that this tool assumes a well formatted nsd.db file.
//
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
)

const (
	A_RECORD      = 1
	AAAA_RECORD   = 28
	CNAME_RECORD  = 5
	DNSKEY_RECORD = 48
	DS_RECORD     = 43
	NS_RECORD     = 2
	NSEC_RECORD   = 47
	RRSIG_RECORD  = 46
	SOA_RECORD    = 6
)

type dnsParseContext struct {
	zones   []string
	domains []string
}

type rrSet struct {
	ctx     *dnsParseContext
	domain  string
	zone    string
	rr_type uint16
	dclass  uint16
	count   uint16
	records []rData
}

type rData struct {
	rr_set *rrSet
	count  uint16
	ttl    uint32
	atoms  []bytesAtom
}

type bytesAtom struct {
	r_data    *rData
	the_bytes []byte
}

func bytesToUint32(the_bytes []byte, enc binary.ByteOrder) uint32 {
	var rawInt uint32
	err := binary.Read(bytes.NewReader(the_bytes), enc, &rawInt)
	if err != nil {
		panic("uh oh")
	}
	return rawInt
}

func bytesToUint16(the_bytes []byte, enc binary.ByteOrder) uint16 {
	var rawInt uint16
	err := binary.Read(bytes.NewReader(the_bytes), enc, &rawInt)
	if err != nil {
		panic("uh oh")
	}
	return rawInt
}

func bytesToUint8(the_bytes []byte, enc binary.ByteOrder) uint8 {
	var rawInt uint8
	err := binary.Read(bytes.NewReader(the_bytes), enc, &rawInt)
	if err != nil {
		panic("uh oh")
	}
	return rawInt
}

func read_uint32(f *os.File) uint32 {
	intCountInBytes := make([]byte, 4)
	_, err4 := f.Read(intCountInBytes)
	if err4 != nil {
		panic(err4)
	}
	return bytesToUint32(intCountInBytes, binary.BigEndian)
}

func read_uint16(f *os.File) uint16 {
	intCountInBytes := make([]byte, 2)
	bytesRead, err4 := f.Read(intCountInBytes)
	if err4 != nil {
		panic(err4)
	}
	if bytesRead != 2 {
		panic("unable to read a full uint16")
	}
	return bytesToUint16(intCountInBytes, binary.BigEndian)
}

func read_uint8(f *os.File) uint8 {
	intCountInBytes := make([]byte, 1)
	_, err4 := f.Read(intCountInBytes)
	if err4 != nil {
		panic(err4)
	}
	return bytesToUint8(intCountInBytes, binary.BigEndian)
}

func aToString(r_data *rData) string {
	ip_bytes := r_data.atoms[0].the_bytes
	return fmt.Sprintf("%s", net.IPv4(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])) // ipv4 address
}

func aaaaToString(r_data *rData) string {
	return fmt.Sprintf("%s", net.IP(r_data.atoms[0].the_bytes)) // ipv6 address
}

func cnameToString(r_data *rData) string {
	return fmt.Sprintf("%s", domainRef(r_data.atoms[0].the_bytes, r_data.rr_set.ctx)) // domain name // todo is this right or do we have to read a domain name here?
}

func nsToString(r_data *rData) string {
	return fmt.Sprintf("%s", domainRef(r_data.atoms[0].the_bytes, r_data.rr_set.ctx)) // nameserver
}

func dsToString(r_data *rData) string {
	return fmt.Sprintf("%d %d %d %x",
		bytesToUint16(r_data.atoms[0].the_bytes, binary.BigEndian), // key tag
		bytesToUint8(r_data.atoms[1].the_bytes, binary.BigEndian),  // algorithm
		bytesToUint8(r_data.atoms[2].the_bytes, binary.BigEndian),  // digest type
		r_data.atoms[3].the_bytes)                                  // digest
}

func soaToString(r_data *rData) string {
	return fmt.Sprintf("%s %s %d %v %v %v %v",
		domainRef(r_data.atoms[0].the_bytes, r_data.rr_set.ctx),
		domainRef(r_data.atoms[1].the_bytes, r_data.rr_set.ctx),
		bytesToUint32(r_data.atoms[2].the_bytes, binary.BigEndian), // serial
		bytesToUint32(r_data.atoms[3].the_bytes, binary.BigEndian), // refresh
		bytesToUint32(r_data.atoms[4].the_bytes, binary.BigEndian), // retry
		bytesToUint32(r_data.atoms[5].the_bytes, binary.BigEndian), // expire
		bytesToUint32(r_data.atoms[6].the_bytes, binary.BigEndian)) // cache
}

func rrsigToString(r_data *rData) string {
	return fmt.Sprintf("%s %v %v %v %v %v %v %v %s",
		type_name(bytesToUint16(r_data.atoms[0].the_bytes, binary.BigEndian)), // type covered
		bytesToUint8(r_data.atoms[1].the_bytes, binary.BigEndian),             // algorithm
		bytesToUint8(r_data.atoms[2].the_bytes, binary.BigEndian),             // labels
		bytesToUint32(r_data.atoms[3].the_bytes, binary.BigEndian),            // original ttl
		bytesToUint32(r_data.atoms[4].the_bytes, binary.BigEndian),            // signature expiration
		bytesToUint32(r_data.atoms[5].the_bytes, binary.BigEndian),            // signature inception
		bytesToUint16(r_data.atoms[6].the_bytes, binary.BigEndian),            // key tag
		domainRef(r_data.atoms[7].the_bytes, r_data.rr_set.ctx),               // signer's name
		base64.StdEncoding.EncodeToString(r_data.atoms[8].the_bytes))          // signature
}

func typeBitMapsToString(the_bytes []byte) string {
	s := ""
	byte_one := int(the_bytes[0])
	window_byte := math.Pow(2, float64(byte_one)) - 1
	bitmap_length := uint8(the_bytes[1])
	if bitmap_length < 1 || bitmap_length > 32 {
		panic("bad bitmap length")
	}
	for i := 0; i < int(bitmap_length); i++ {
		bytes_so_far := i * 8
		the_byte := the_bytes[i+2]
		for b := 0; b < 8; b++ {
			bit_set := (the_byte&(0x01<<uint8(7-b)) > 0)
			if bit_set {
				t := uint16(int(window_byte) + bytes_so_far + b)
				tStr := type_name(t)
				s += fmt.Sprintf("%s ", tStr)
			}

		}
	}
	return s
}

func nsecToString(r_data *rData) string {
	return fmt.Sprintf("%v %s",
		domainRef(r_data.atoms[0].the_bytes, r_data.rr_set.ctx), // next domain name
		typeBitMapsToString(r_data.atoms[1].the_bytes))          // type bit maps
}

func dnskeyToString(r_data *rData) string {
	return fmt.Sprintf("%d %d %d %s",
		bytesToUint16(r_data.atoms[0].the_bytes, binary.BigEndian),   // flags
		bytesToUint8(r_data.atoms[1].the_bytes, binary.BigEndian),    // protocol
		bytesToUint8(r_data.atoms[2].the_bytes, binary.BigEndian),    // algorithm
		base64.StdEncoding.EncodeToString(r_data.atoms[3].the_bytes)) // public key (format depends on previous values)
}

func (rr_set *rrSet) String() string {
	s := ""
	for _, rr := range rr_set.records {
		s += fmt.Sprintf("\n%s", rr)
	}
	s += "\n"
	return s
}

func (r_data rData) String() string {
	rr_type := r_data.rr_set.rr_type

	s := fmt.Sprintf("%s %d %s %s ", r_data.rr_set.domain, r_data.ttl, class_name(r_data.rr_set.dclass), type_name(r_data.rr_set.rr_type))

	if rr_type == A_RECORD {
		s += aToString(&r_data)
	} else if rr_type == NS_RECORD {
		s += nsToString(&r_data)
	} else if rr_type == CNAME_RECORD {
		s += cnameToString(&r_data)
	} else if rr_type == SOA_RECORD {
		s += soaToString(&r_data)
	} else if rr_type == AAAA_RECORD {
		s += aaaaToString(&r_data)
	} else if rr_type == DS_RECORD {
		s += dsToString(&r_data)
	} else if rr_type == RRSIG_RECORD {
		s += rrsigToString(&r_data)
	} else if rr_type == NSEC_RECORD {
		s += nsecToString(&r_data)
	} else if rr_type == DNSKEY_RECORD {
		s += dnskeyToString(&r_data)
	} else {
		for _, atm := range r_data.atoms {
			s += fmt.Sprintf("%v ", atm.the_bytes)
		}
	}

	return s
}

func read_magic(f *os.File) string {
	magic_arr := make([]byte, 8)
	bytesRead, err2 := f.Read(magic_arr)
	if err2 != nil {
		panic(err2)
	}
	if bytesRead != 8 {
		panic(fmt.Sprintf("did not read entire magic (read %d of %d)", bytesRead, 8))
	}
	return string(magic_arr)
}

func read_domain(f *os.File, ctx *dnsParseContext) string {
	domainIndex := read_uint32(f)
	return domainByIndex(domainIndex, ctx)
}

func domainRef(the_bytes []byte, ctx *dnsParseContext) string {
	domainIndex := bytesToUint32(the_bytes, binary.BigEndian)
	return domainByIndex(domainIndex, ctx)
}

func domainByIndex(domainIndex uint32, ctx *dnsParseContext) string {
	if int(domainIndex) == 0 {
		return ""
	}
	if int(domainIndex) > len(ctx.domains) {
		return ""
	}
	return ctx.domains[domainIndex-1]
}

func rdata_atom_is_domain(rr_type uint16, y int) bool {
	if rr_type == NS_RECORD { // ns
		return true
	} else if rr_type == NSEC_RECORD && y == 0 { // nsec (1st part)
		return true
	} else if rr_type == RRSIG_RECORD && y == 7 { // rrsig (8th part)
		return true
	} else if rr_type == SOA_RECORD && (y == 0 || y == 1) { // soa (1st and 2nd part)
		return true
	}
	return false
}

func read_rdata_atom(f *os.File, ctx *dnsParseContext, r_data *rData, y int) (bytesAtom, error) {
	rr_type := r_data.rr_set.rr_type
	if rdata_atom_is_domain(rr_type, y) {
		byts := make([]byte, 4)
		bytesRead, err := f.Read(byts)
		if err != nil {
			panic(err)
		}
		if bytesRead != 4 {
			panic("did not read the correct number of bytes")
		}
		bytes_atom := bytesAtom{r_data, byts}
		return bytes_atom, nil
	} else {
		sz := read_uint16(f)
		byts := make([]byte, sz)
		bytesRead, err := f.Read(byts)
		if err != nil || bytesRead != int(sz) {
			panic(err)
		}
		bytes_atom := bytesAtom{r_data, byts}
		return bytes_atom, nil
	}
}

func read_zone(f *os.File, ctx *dnsParseContext) string {
	zoneIndex := read_uint32(f)
	// fmt.Printf("reading zone %d which is %s\n", zoneIndex-1, ctx.zones[zoneIndex-1])
	return ctx.zones[zoneIndex-1]
}

func class_name(c uint16) string {
	if c == 1 {
		return "IN"
	} else {
		return "unknown"
	}
}

func type_name(t uint16) string {
	if t == NS_RECORD {
		return "NS"
	} else if t == DS_RECORD {
		return "DS"
	} else if t == DNSKEY_RECORD {
		return "DNSKEY"
	} else if t == NSEC_RECORD {
		return "NSEC"
	} else if t == RRSIG_RECORD {
		return "RRSIG"
	} else if t == SOA_RECORD {
		return "SOA"
	} else if t == A_RECORD {
		return "A"
	} else if t == AAAA_RECORD {
		return "AAAA"
	} else if t == CNAME_RECORD {
		return "CNAME"
	} else {
		return "unknown"
	}

}

func read_rrset(f *os.File, ctx *dnsParseContext) *rrSet {
	rr_set := rrSet{ctx: ctx}
	domain := read_domain(f, ctx)
	if domain == "" {
		return nil
	}
	rr_set.domain = domain
	rr_set.zone = read_zone(f, ctx)
	rr_set.rr_type = read_uint16(f)
	rr_set.dclass = read_uint16(f)
	rr_set.count = read_uint16(f)
	rr_set.records = make([]rData, rr_set.count)
	for i := 0; i < int(rr_set.count); i++ {
		r_data := rData{rr_set: &rr_set}
		r_data.count = read_uint16(f)
		r_data.ttl = read_uint32(f)
		r_data.atoms = make([]bytesAtom, int(r_data.count))
		for y := 0; y < int(r_data.count); y++ {
			r_data_atom, err := read_rdata_atom(f, ctx, &r_data, y)
			if err != nil {
				return nil
			}
			r_data.atoms[y] = r_data_atom
		}
		rr_set.records[i] = r_data
	}
	// todo add tsig logic
	return &rr_set
}

func read_dname(f *os.File) string {
	//read the size of the dname
	sizeCount := read_uint8(f)

	//read that size
	dNameBuffer := make([]byte, sizeCount)
	cnt, err := f.Read(dNameBuffer)
	if err != nil {
		panic(err)
	}
	if cnt != int(sizeCount) {
		panic(fmt.Sprintf("Only partially read a dname. Read %d of %d.\n", cnt, sizeCount))
	}

	cleanBuffer := make([]byte, sizeCount)
	cleanIdx := 0
	remainingBytesToRead := 0
	for i := 0; i < int(sizeCount); i++ {
		if remainingBytesToRead == 0 {
			remainingBytesToRead = int(dNameBuffer[i])
			if i != 0 {
				cleanBuffer[cleanIdx] = byte('.')
				cleanIdx++
			}
		} else {
			cleanBuffer[cleanIdx] = dNameBuffer[i]
			cleanIdx++
			remainingBytesToRead--
		}
	}

	// remove trainling null terminator
	cleanBuffer = cleanBuffer[0 : len(cleanBuffer)-1]

	return string(cleanBuffer)
}

func read_and_save_dname(f *os.File, ctx *dnsParseContext, idx int) string {
	dname := read_dname(f)
	ctx.domains[idx] = dname
	return dname
}

func read_and_save_zone_dname(f *os.File, ctx *dnsParseContext, idx int) string {
	dname := read_dname(f)
	ctx.zones[idx] = dname
	return dname
}

func main() {

	var ver bool
	var dbg bool
	var fname string

	flag.BoolVar(&ver, "v", false, "print the version")
	flag.BoolVar(&dbg, "d", false, "print extra debug information")
	flag.StringVar(&fname, "f", "", "the file to parse and print")

	flag.Parse()

	if ver {
		fmt.Printf("Version: 1.0.1\n")
		return
	}

	if fname == "" {
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
		return
	}

	f, err := os.Open(fname)
	if err != nil {
		panic(err)
	}

	// this will hold values that will be referenced by index later
	ctx := dnsParseContext{}

	//readmagic
	magic := read_magic(f)
	if dbg {
		fmt.Printf("magic: %s\n", magic)
	}

	//read int for zonecount
	zoneCount := read_uint32(f)
	if dbg {
		fmt.Printf("ZoneCount: %d\n", zoneCount)
	}

	ctx.zones = make([]string, zoneCount)

	//iterate and print zones
	for i := 0; i < int(zoneCount); i++ {
		zone := read_and_save_zone_dname(f, &ctx, i)
		if dbg {
			fmt.Printf("zone: %3d - %s\n", i+1, zone)
		}
	}

	// dname count
	dnameCount := read_uint32(f)
	if dbg {
		fmt.Printf("dname count: %d\n", dnameCount)
	}

	ctx.domains = make([]string, dnameCount)

	// iterate and print dnames
	for i := 0; i < int(dnameCount); i++ {
		rr := read_and_save_dname(f, &ctx, i)
		if dbg {
			fmt.Printf("dname: %3d - %s\n", i+1, rr)
		}
	}

	// iterate and print rr sets
	rrSet := read_rrset(f, &ctx)
	for rrSet != nil {
		fmt.Printf("%s", rrSet)
		rrSet = read_rrset(f, &ctx)

	}

	crc := read_uint32(f)
	if dbg {
		fmt.Printf("\ncrc: %d\n", crc)
	}

	end_magic := read_magic(f)
	if dbg {
		fmt.Printf("Magic: %s\n", end_magic)
	}

}
