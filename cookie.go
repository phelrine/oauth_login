package oauth_login

import (
	"net"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type Cookie struct {
	Name     string
	HttpOnly bool
	Secure   bool
	Age      time.Duration
	sc       *securecookie.SecureCookie
}

func NewCookie(secret string) *Cookie {
	// The hashKey is required, used to authenticate the cookie value using
	// HMAC. It is recommended to use a key with 32 or 64 bytes.
	// The blockKey is optional, used to encrypt the cookie value -- set it to
	// nil to not use encryption. If set, the length must correspond to the
	// block size of the encryption algorithm. For AES, used by default, valid
	// lengths are 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
	key := []byte(secret)
	return &Cookie{
		Name:     "_oauth2",
		HttpOnly: true,
		Secure:   false,
		Age:      time.Hour * 720,
		sc:       securecookie.New(key, key),
	}
}

func (c *Cookie) Load(r *http.Request) (*Session, error) {
	raw, err := r.Cookie(c.Name)
	if err != nil {
		if err != http.ErrNoCookie {
			return nil, err
		}
		return nil, nil
	}

	var session Session
	if err := c.sc.Decode(c.Name, raw.Value, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (c *Cookie) Save(w http.ResponseWriter, r *http.Request, s *Session) error {
	enc, err := c.sc.Encode(c.Name, s)
	if err != nil {
		return err
	}
	c.setCookie(w, r, enc)
	return nil
}

func (c *Cookie) makeCookie(req *http.Request, value string, expiration time.Duration) *http.Cookie {
	now := time.Now()
	raw := &http.Cookie{
		Name:     c.Name,
		Value:    value,
		Path:     "/",
		HttpOnly: c.HttpOnly,
		Secure:   c.Secure,
		Expires:  now.Add(expiration),
	}
	if host, _, err := net.SplitHostPort(req.Host); err != nil {
		panic(err)
	} else {
		raw.Domain = host
	}
	return raw
}

func (c *Cookie) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, c.makeCookie(r, "", time.Hour*-1))
}

func (c *Cookie) setCookie(w http.ResponseWriter, r *http.Request, v string) {
	http.SetCookie(w, c.makeCookie(r, v, c.Age))
}
