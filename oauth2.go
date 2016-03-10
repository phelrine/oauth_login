package oauth_login

import (
	"net/http"

	"golang.org/x/oauth2"
)

type Session struct {
	User  string
	Email string
	Token *oauth2.Token
}

type OAuth2 struct {
	provider Provider
	cookie   *Cookie
}

func New(provider Provider, cookie *Cookie) *OAuth2 {
	return &OAuth2{
		provider: provider,
		cookie:   cookie,
	}
}

func (o *OAuth2) Redirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	url := o.provider.AuthCodeURL(next, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (o *OAuth2) Callback(w http.ResponseWriter, r *http.Request) (*Session, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	code := r.Form.Get("code")
	token, err := o.provider.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	session, err := o.provider.GetSession(token)
	if err != nil {
		return nil, err
	}

	if err := o.cookie.Save(w, r, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (o *OAuth2) Authenticate(r *http.Request) (*Session, error) {
	session, err := o.cookie.Load(r)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (o *OAuth2) Logout(w http.ResponseWriter, r *http.Request) {
	o.cookie.clearCookie(w, r)
}

func (o *OAuth2) RequestURI(r *http.Request) string {
	return r.Form.Get("state")
}
