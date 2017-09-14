package ldaputil

import (
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

func TestConnect(t *testing.T) {
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
	require.True(t, ok, "va[%d] = \"\"", i)
	var ld *Ldap
	var e error
	ld, e = NewLdap(adAddr, adSuff, adBDN)
	require.NoError(t, e)
	e = ld.Authenticate(uprUser, uprPass)
	require.NoError(t, e)
	var rec map[string][]string
	rec, e = ld.FullRecord(uprUser)
	require.NoError(t, e)
	for k, v := range rec {
		t.Logf("%s: %v", k, v)
	}
}
