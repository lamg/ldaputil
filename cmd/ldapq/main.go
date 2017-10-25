package main

import (
	"flag"
	"fmt"
	"github.com/lamg/ldaputil"
	"log"
)

func main() {
	var addr, suff, bDN, user, pass, quser string
	flag.StringVar(&addr, "a", "", "LDAP server address")
	flag.StringVar(&suff, "s", "", "LDAP server account suffix")
	flag.StringVar(&bDN, "b", "", "LDAP server base DN")
	flag.StringVar(&user, "u", "",
		"LDAP server user name for binding")
	flag.StringVar(&pass, "p", "",
		"LDAP server password for binding")
	flag.StringVar(&quser, "q", "",
		"LDAP user name to consult its record")
	flag.Parse()
	ld := ldaputil.NewLdap(addr, suff, bDN, user, pass)
	rec, e := ld.FullRecord(quser)
	if e == nil {
		for k, v := range rec {
			fmt.Printf("%s:\n", k)
			for _, j := range v {
				fmt.Printf("    %v\n", j)
			}
		}
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
