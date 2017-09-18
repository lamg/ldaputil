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
	// OU beginning of group specification in AD
	OU = "OU="
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
	c      *ldap.Conn
	baseDN string
	sf     string
}

// NewLdap creates a new instance of Ldap
// addr: LDAP server address (IP ":" PortNumber)
// suff: User account suffix
// bDN: baseDN
// admG: Administrators group name
func NewLdap(addr, suff, bDN string) (l *Ldap, e *errors.Error) {
	l = new(Ldap)
	var c *ldap.Conn
	c, e = NewLdapConn(addr)
	if e == nil {
		l.Init(c, suff, bDN)
	}
	return
}

// NewLdapConn creates a new connection to an LDAP server at
// addr using TLS
func NewLdapConn(addr string) (c *ldap.Conn, e *errors.Error) {
	var cfg *tls.Config
	cfg = &tls.Config{InsecureSkipVerify: true}
	var ec error
	c, ec = ldap.DialTLS("tcp", addr, cfg)
	if ec != nil {
		e = &errors.Error{Code: ErrorNetwork, Err: ec}
	}
	return
}

// Init initializes an Ldap object with previously initialized
// variables to be its internal fields
func (l *Ldap) Init(c *ldap.Conn, suff, bDN string) {
	l.c, l.sf, l.baseDN = c, suff, bDN
}

// Authenticate authenticates an user u with password p
func (l *Ldap) Authenticate(u, p string) (e *errors.Error) {
	var ec error
	ec = l.c.Bind(string(u)+l.sf, p)
	if ec != nil {
		e = &errors.Error{Code: ErrorAuth, Err: ec}
	}
	return
}

// Membership obtains the current membership of user usr
func (l *Ldap) Membership(usr string) (m []string, e error) {
	var mp map[string][]string
	mp, e = l.FullRecord(usr)
	if e == nil {
		m = mp[MemberOf]
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

// GetGroup gets the group specified at distinguishedName field
// usr: sAMAccountName
func (l *Ldap) GetGroup(usr string) (g string, e *errors.Error) {
	var mp map[string][]string
	mp, e = l.FullRecord(usr)
	if e == nil {
		s, ok := mp[DistinguishedName]
		if !ok {
			e = &errors.Error{
				Code: ErrorSearch,
				Err:  fmt.Errorf("Distinguished name for %s not found", usr),
			}
		} else {
			if len(s) > 0 {
				sl := strings.Split(s[0], ",")
				if len(sl) > 1 {
					oul := sl[1]
					if strings.HasPrefix(oul, OU) {
						g = strings.TrimLeft(oul, OU)
					} else {
						e = &errors.Error{
							Code: ErrorFormat,
							Err:  fmt.Errorf("%v has no string with prefix %s at 1", s, OU),
						}
					}
				} else {
					e = &errors.Error{
						Code: ErrorFormat,
						Err:  fmt.Errorf("Length of %s field should be > 1", DistinguishedName),
					}
				}
			} else {
				e = &errors.Error{
					Code: ErrorFormat,
					Err:  fmt.Errorf("Length of %s should be > 0", DistinguishedName),
				}
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
	r, ec := l.c.Search(s)
	if ec == nil && len(r.Entries) == 0 || ec != nil {
		e = &errors.Error{Code: ErrorSearch}
		if ec == nil {
			e.Err = fmt.Errorf("Failed search of %s", f)
		} else {
			e.Err = ec
		}
	} else if ec == nil {
		n = r.Entries
	}
	return
}
