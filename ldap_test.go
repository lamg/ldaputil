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
	uprUser = os.Getenv("UPR_USER")
	uprPass = os.Getenv("UPR_PASS")
)

func initLdapTest() (l *Ldap, e *errors.Error) {
	var ok bool
	va := []string{adAddr, adSuff, adBDN, uprUser, uprPass}
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
		l = NewLdap(adAddr, adSuff, adBDN)
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
		rec, e = ld.FullRecord(uprUser, uprPass, uprUser)
		require.True(t, e == nil)
		for k, v := range rec {
			t.Logf("%s: %v", k, v)
		}
	}
}

func TestMembershipCNs(t *testing.T) {
	ld, e := initLdapTest()
	require.True(t, e == nil)
	var mp map[string][]string
	mp, e = ld.FullRecord(uprUser, uprPass, uprUser)
	require.True(t, e == nil)
	var m []string
	m, e = ld.MembershipCNs(mp)
	require.True(t, e == nil && len(m) > 0, "m=%d", len(m))
	t.Logf("%v", m)
}

func TestDNFirstGroup(t *testing.T) {
	ld, e := initLdapTest()
	require.True(t, e == nil)
	var mp map[string][]string
	mp, e = ld.FullRecord(uprUser, uprPass, uprUser)
	require.True(t, e == nil)
	var d string
	d, e = ld.DNFirstGroup(mp)
	require.True(t, e == nil && len(d) > 0)
	t.Log(d)
}

func TestGetAccountName(t *testing.T) {
	ld, e := initLdapTest()
	require.True(t, e == nil)
	mp, e := ld.FullRecord(uprUser, uprPass, uprUser)
	require.True(t, e == nil)
	usr, e := ld.GetAccountName(mp)
	require.True(t, e == nil)
	require.Equal(t, uprUser, usr)
}
