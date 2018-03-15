package ldaputil

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	adAddr = os.Getenv("AD")
	adSuff = os.Getenv("AD_SUFF")
	adBDN  = os.Getenv("AD_BDN")
	user   = os.Getenv("USER")
	pass   = os.Getenv("PASS")
)

func initLdapTest() (l *Ldap, e error) {
	var ok bool
	va := []string{adAddr, adSuff, adBDN, user, pass}
	var i int
	ok, i = true, 0
	for ok && i != len(va) {
		ok = va[i] != ""
		if ok {
			i = i + 1
		}
	}
	if !ok {
		e = fmt.Errorf("va[%d] = \"\"", i)
	} else {
		l = NewLdap(adAddr, adSuff, adBDN)
	}
	return
}

func TestFullRecord(t *testing.T) {
	ld, e := initLdapTest()
	require.NoError(t, e)
	var rec map[string][]string
	rec, e = ld.FullRecord(user, pass, user)
	require.NoError(t, e)
	for k, v := range rec {
		t.Logf("%s: %v", k, v)
	}
}

func TestMembershipCNs(t *testing.T) {
	ld, e := initLdapTest()
	require.NoError(t, e)
	var mp map[string][]string
	mp, e = ld.FullRecord(user, pass, user)
	require.NoError(t, e)
	var m []string
	m, e = ld.MembershipCNs(mp)
	require.NoError(t, e)
	require.True(t, len(m) > 0, "m=%d", len(m))
}

func TestDNFirstGroup(t *testing.T) {
	ld, e := initLdapTest()
	require.NoError(t, e)
	var mp map[string][]string
	mp, e = ld.FullRecord(user, pass, user)
	require.NoError(t, e)
	var d string
	d, e = ld.DNFirstGroup(mp)
	require.NoError(t, e)
	require.True(t, len(d) > 0, "d=%d", d)
}

func TestGetAccountName(t *testing.T) {
	ld, e := initLdapTest()
	require.NoError(t, e)
	mp, e := ld.FullRecord(user, pass, user)
	require.NoError(t, e)
	usr, e := ld.GetAccountName(mp)
	require.NoError(t, e)
	require.Equal(t, user, usr)
}
