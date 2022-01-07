package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"net"
	"regexp"
)

var (
	typesMap = map[string]uint16{
		"None":       dns.TypeNone,
		"A":          dns.TypeA,
		"NS":         dns.TypeNS,
		"MD":         dns.TypeMD,
		"MF":         dns.TypeMF,
		"CNAME":      dns.TypeCNAME,
		"SOA":        dns.TypeSOA,
		"MB":         dns.TypeMB,
		"MG":         dns.TypeMG,
		"MR":         dns.TypeMR,
		"NULL":       dns.TypeNULL,
		"PTR":        dns.TypePTR,
		"HINFO":      dns.TypeHINFO,
		"MINFO":      dns.TypeMINFO,
		"MX":         dns.TypeMX,
		"TXT":        dns.TypeTXT,
		"RP":         dns.TypeRP,
		"AFSDB":      dns.TypeAFSDB,
		"X25":        dns.TypeX25,
		"ISDN":       dns.TypeISDN,
		"RT":         dns.TypeRT,
		"NSAPPTR":    dns.TypeNSAPPTR,
		"SIG":        dns.TypeSIG,
		"KEY":        dns.TypeKEY,
		"PX":         dns.TypePX,
		"GPOS":       dns.TypeGPOS,
		"AAAA":       dns.TypeAAAA,
		"LOC":        dns.TypeLOC,
		"NXT":        dns.TypeNXT,
		"EID":        dns.TypeEID,
		"NIMLOC":     dns.TypeNIMLOC,
		"SRV":        dns.TypeSRV,
		"ATMA":       dns.TypeATMA,
		"NAPTR":      dns.TypeNAPTR,
		"KX":         dns.TypeKX,
		"CERT":       dns.TypeCERT,
		"DNAME":      dns.TypeDNAME,
		"OPT":        dns.TypeOPT,
		"APL":        dns.TypeAPL,
		"DS":         dns.TypeDS,
		"SSHFP":      dns.TypeSSHFP,
		"RRSIG":      dns.TypeRRSIG,
		"NSEC":       dns.TypeNSEC,
		"DNSKEY":     dns.TypeDNSKEY,
		"DHCID":      dns.TypeDHCID,
		"NSEC3":      dns.TypeNSEC3,
		"NSEC3PARAM": dns.TypeNSEC3PARAM,
		"TLSA":       dns.TypeTLSA,
		"SMIMEA":     dns.TypeSMIMEA,
		"HIP":        dns.TypeHIP,
		"NINFO":      dns.TypeNINFO,
		"RKEY":       dns.TypeRKEY,
		"TALINK":     dns.TypeTALINK,
		"CDS":        dns.TypeCDS,
		"CDNSKEY":    dns.TypeCDNSKEY,
		"OPENPGPKEY": dns.TypeOPENPGPKEY,
		"CSYNC":      dns.TypeCSYNC,
		"ZONEMD":     dns.TypeZONEMD,
		"SVCB":       dns.TypeSVCB,
		"HTTPS":      dns.TypeHTTPS,
		"SPF":        dns.TypeSPF,
		"UINFO":      dns.TypeUINFO,
		"UID":        dns.TypeUID,
		"GID":        dns.TypeGID,
		"UNSPEC":     dns.TypeUNSPEC,
		"NID":        dns.TypeNID,
		"L32":        dns.TypeL32,
		"L64":        dns.TypeL64,
		"LP":         dns.TypeLP,
		"EUI48":      dns.TypeEUI48,
		"EUI64":      dns.TypeEUI64,
		"URI":        dns.TypeURI,
		"CAA":        dns.TypeCAA,
		"AVC":        dns.TypeAVC,
		"TKEY":       dns.TypeTKEY,
		"TSIG":       dns.TypeTSIG,
		"IXFR":       dns.TypeIXFR,
		"AXFR":       dns.TypeAXFR,
		"MAILB":      dns.TypeMAILB,
		"MAILA":      dns.TypeMAILA,
		"ANY":        dns.TypeANY,
		"TA":         dns.TypeTA,
		"DLV":        dns.TypeDLV,
		"Reserved":   dns.TypeReserved,
	}
	classesMap = map[string]uint16{
		"INET":   dns.ClassINET,
		"CSNET":  dns.ClassCSNET,
		"CHAOS":  dns.ClassCHAOS,
		"HESIOD": dns.ClassHESIOD,
		"NONE":   dns.ClassNONE,
		"ANY":    dns.ClassANY,
	}
)

func resolve(cmd *cobra.Command, args []string) error {
	host := cmd.Flag("host").Value.String()
	port := cmd.Flag("port").Value.String()
	qType := cmd.Flag("type").Value.String()
	qClass := cmd.Flag("class").Value.String()

	domain := args[0]

	client := new(dns.Client)
	message := new(dns.Msg)

	message.Id = dns.Id()
	message.RecursionDesired = true

	message.Question = make([]dns.Question, 1)
	message.Question[0] = dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  typesMap[qType],
		Qclass: classesMap[qClass],
	}

	resp, _, err := client.Exchange(message, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("invalid answer name %s after CNAME query for %s", domain, domain))
	}
	for _, answer := range resp.Answer {
		fmt.Println(answer.String())
	}
	return nil
}

func initCommand() *cobra.Command {
	return &cobra.Command{
		Use:                   "gresolver -H [SERVER] [DOMAIN]",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		Example:               "gresolver -H 192.168.1.2 xxx.yyy.zzz",
		Short:                 "gresolver is a dns client that can specify a DNS server.",
		PreRunE:               checkArgsAndFlags,
		RunE:                  resolve,
	}
}

func checkArgsAndFlags(cmd *cobra.Command, args []string) error {
	f := cobra.ExactArgs(1)
	if err := f(cmd, args); err != nil {
		return err
	}
	if !validDomain(args[0]) {
		return errors.New(fmt.Sprintf("%s is not a valid domain", args[0]))
	}
	qType := cmd.Flag("type").Value.String()
	if _, ok := typesMap[qType]; !ok {
		return errors.New("invalid query type")
	}
	qClass := cmd.Flag("class").Value.String()
	if _, ok := classesMap[qClass]; !ok {
		return errors.New("invalid query class")
	}
	return nil
}

func validDomain(text string) bool {
	re := regexp.MustCompile("^(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}$")
	return re.MatchString(text)
}

func setupRootCmd(cmd *cobra.Command) {
	cmd.PersistentFlags().StringP("host", "H", "223.5.5.5", "DNS server")
	cmd.PersistentFlags().StringP("port", "p", "53", "DNS server port")
	cmd.PersistentFlags().StringP("type", "t", "A", "query type, possible values: None, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, NSAPPTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, DNAME, OPT, APL, DS, SSHFP, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SMIMEA, HIP, NINFO, RKEY, TALINK, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, SPF, UINFO, UID, GID, UNSPEC, NID, L32, L64, LP, EUI48, EUI64, URI, CAA, AVC, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY, TA, DLV, Reserved")
	cmd.PersistentFlags().StringP("class", "c", "INET", "query class, possible values: INET, CSNET, CHAOS, HESIOD, NONE, ANY")
}

func main() {
	cmd := initCommand()
	setupRootCmd(cmd)
	cmd.Execute()
}
