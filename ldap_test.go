package ldaputil

import (
	"fmt"
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	adAddr  = os.Getenv("AD")
	adSuff  = os.Getenv("AD_SUFF")
	adBDN   = os.Getenv("AD_BDN")
	adAdmG  = os.Getenv("AD_ADMG")
	uprUser = os.Getenv("UPR_USER")
	uprPass = os.Getenv("UPR_PASS")
)

func initLdapTest() (l *Ldap, e *errors.Error) {
	var ok bool
	va := []string{adAddr, adSuff, adBDN, adAdmG, uprUser, uprPass}
	var i int
	ok, i = true, 0
	for ok && i != len(va) {
		ok = va[i] != ""
		if ok {
			i = i + 1
		}
	}
	if !ok {
		e = &errors.Error{Code: 0, Err: fmt.Errorf("va[%d] = \"\"", i)}
	} else {
		l, e = NewLdap(adAddr, adSuff, adBDN)
	}
	if e == nil {
		e = l.Authenticate(uprUser, uprPass)
	}
	return
}
func TestFullRecord(t *testing.T) {
	ld, e := initLdapTest()
	if e != nil && e.Code == ErrorNetwork {
		t.Log(e.Error())
	} else {
		require.True(t, e == nil)
		var rec map[string][]string
		rec, e = ld.FullRecord(uprUser)
		require.True(t, e == nil)
		for k, v := range rec {
			t.Logf("%s: %v", k, v)
		}
	}
}

func TestMembershipCNs(t *testing.T) {
	ld, e := initLdapTest()
	require.True(t, e == nil)
	var m []string
	m, e = ld.MembershipCNs(uprUser)
	require.True(t, e == nil && len(m) > 0)
	t.Logf("%v", m)
}

func TestDNFirstGroup(t *testing.T) {
	ld, e := initLdapTest()
	require.True(t, e == nil)
	var d string
	d, e = ld.DNFirstGroup(uprUser)
	require.True(t, e == nil && len(d) > 0)
	t.Log(d)
}
