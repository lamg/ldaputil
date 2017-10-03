package ldaputil

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/lamg/errors"
	"strings"
)

const (
	// MemberOf is the memberOf key in an LDAP record
	MemberOf = "memberOf"
	// CN is the cn key in an LDAP record
	CN = "cn"
	// DistinguishedName is the name of the distinguishedName
	// field
	DistinguishedName = "distinguishedName"
	// ou beginning of group specification in AD
	ouPref = "OU="
	// cnPref
	cnPref = "CN="
)

const (
	// ErrorAuth is the code for authentication errors
	ErrorAuth = iota
	// ErrorNetwork is the code of the error returned when
	// there's no network connection
	ErrorNetwork
	// ErrorMoreThanOne is the code when SearchOne founds
	// more than one result
	ErrorMoreThanOne
	// ErrorSearch is the code for SearchFilter errors
	ErrorSearch
	//ErrorFormat is the code when a field in AD is malformed
	ErrorFormat
)

// Ldap is the object that handles the connection to an LDAP
// server
type Ldap struct {
	addr   string
	user   string
	pass   string
	baseDN string
	suff   string
}

// NewLdap creates a new instance of Ldap
// addr: LDAP server address (IP ":" PortNumber)
// sf: User account suffix
// bDN: baseDN
// admG: Administrators group name
// u: user
// p: password
func NewLdap(addr, sf, bDN, u, p string) (l *Ldap) {
	l = &Ldap{addr: addr, user: u, pass: p, baseDN: bDN, suff: sf}
	return
}

// newConn creates a new connection to an LDAP server at
// l.addr using TLS
func (l *Ldap) newConn() (c *ldap.Conn, e *errors.Error) {
	var cfg *tls.Config
	cfg = &tls.Config{InsecureSkipVerify: true}
	var ec error
	c, ec = ldap.DialTLS("tcp", l.addr, cfg)
	if ec != nil {
		e = &errors.Error{Code: ErrorNetwork, Err: ec}
	}
	return
}

// Authenticate authenticates an user u with password p
func (l *Ldap) Authenticate(u, p string) (c *ldap.Conn, e *errors.Error) {
	c, e = l.newConn()
	if e == nil {
		ec := c.Bind(string(l.user)+l.suff, l.pass)
		if ec != nil {
			c.Close()
			e = &errors.Error{Code: ErrorAuth, Err: ec}
		}
	}
	return
}

// MembershipCNs obtains the current membership of user usr
func (l *Ldap) MembershipCNs(usr string) (m []string,
	e *errors.Error) {
	var mp map[string][]string
	mp, e = l.FullRecord(usr)
	var ok bool
	var ms []string
	if e == nil {
		ms, ok = mp[MemberOf]
	}
	if e == nil && !ok {
		e = &errors.Error{
			Code: ErrorSearch,
			Err:  fmt.Errorf("Couldn't get membership of %s", usr),
		}
	}
	if e == nil {
		m = make([]string, 0)
		for _, j := range ms {
			if strings.HasPrefix(j, cnPref) {
				ns := strings.TrimLeft(j, cnPref)
				ns = strings.Split(ns, ",")[0]
				m = append(m, ns)
			}
		}
	}
	return
}

// DNFirstGroup returns the distinguishedName's first group
// (first value with "OU=" as prefix)
func (l *Ldap) DNFirstGroup(usr string) (d string,
	e *errors.Error) {
	var mp map[string][]string
	mp, e = l.FullRecord(usr)
	var ok bool
	var m []string
	if e == nil {
		m, ok = mp[DistinguishedName]
	}
	if e == nil && !ok {
		e = &errors.Error{
			Code: ErrorSearch,
			Err:  fmt.Errorf("Couldn't get DN of %s", usr),
		}
	}
	if e == nil && len(m) > 0 {
		i, ms, ok := 0, strings.Split(m[0], ","), false
		for !ok && i != len(ms) {
			ok = strings.HasPrefix(ms[i], ouPref)
			if !ok {
				i = i + 1
			}
		}
		if ok {
			d = strings.TrimLeft(ms[i], ouPref)
		} else {
			e = &errors.Error{
				Code: ErrorFormat,
				Err: fmt.Errorf("%s has no value with prefix %s",
					DistinguishedName, ouPref),
			}
		}
	}
	return
}

// FullName gets the CN of user with sAMAccountName usr
func (l *Ldap) FullName(usr string) (m string, e *errors.Error) {
	var mp map[string][]string
	mp, e = l.FullRecord(usr)
	if e == nil {
		s, ok := mp[CN]
		if ok && len(s) == 1 {
			m = s[0]
		} else if !ok {
			e = &errors.Error{
				Code: ErrorSearch,
				Err:  fmt.Errorf("Full name not found (CN field in AD record)"),
			}
		} else if len(s) != 1 {
			e = &errors.Error{
				Code: ErrorSearch,
				Err:  fmt.Errorf("Full name field length is %d instead of 1", len(s)),
			}
		}
	}
	return
}

// FullRecord Gets the full record of an user, using its
//  sAMAccountName field.
func (l *Ldap) FullRecord(usr string) (m map[string][]string,
	e *errors.Error) {
	var n *ldap.Entry
	var filter string
	var atts []string
	filter, atts =
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))",
			usr),
		[]string{}
	n, e = l.SearchOne(filter, atts)
	if e == nil {
		m = make(map[string][]string)
		for _, j := range n.Attributes {
			m[j.Name] = j.Values
		}
	}
	return
}

// SearchOne searchs the first result of applying the filter f
func (l *Ldap) SearchOne(f string,
	ats []string) (n *ldap.Entry, e *errors.Error) {
	var ns []*ldap.Entry
	ns, e = l.SearchFilter(f, ats)
	if e == nil {
		if len(ns) == 1 {
			n = ns[0]
		} else {
			e = &errors.Error{
				Code: ErrorMoreThanOne,
				Err:  fmt.Errorf("Result length = %d", len(ns)),
			}
		}
	}
	return
}

// SearchFilter searchs all the result passing the filter f
func (l *Ldap) SearchFilter(f string,
	ats []string) (n []*ldap.Entry, e *errors.Error) {
	var (
		scope = ldap.ScopeWholeSubtree
		deref = ldap.NeverDerefAliases
		sizel = 0
		timel = 0
		tpeol = false        //TypesOnly
		conts []ldap.Control //[]Control
	)
	s := ldap.NewSearchRequest(l.baseDN, scope, deref,
		sizel, timel, tpeol, f, ats, conts)
	var c *ldap.Conn
	c, e = l.Authenticate(l.user, l.pass)
	var r *ldap.SearchResult
	if e == nil {
		var ec error
		r, ec = c.Search(s)
		if ec != nil {
			e = &errors.Error{
				Code: ErrorSearch,
				Err:  ec,
			}
		}
		c.Close()
	}
	if e == nil && len(r.Entries) == 0 {
		e = &errors.Error{
			Code: ErrorSearch,
			Err:  fmt.Errorf("Failed search of %s", f),
		}
	} else if e == nil {
		n = r.Entries
	}
	return
}
