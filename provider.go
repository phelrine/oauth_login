package oauth2

import (
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	google_api "google.golang.org/api/oauth2/v2"
)

type Provider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetSession(*oauth2.Token) (*Session, error)
}

type googleProvider struct {
	*oauth2.Config
}

func NewGoogleProvider(id, secret string, callback string) Provider {
	return &googleProvider{
		Config: &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			RedirectURL:  callback,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"profile", "email"},
		},
	}
}

func (p *googleProvider) GetSession(token *oauth2.Token) (*Session, error) {
	client := p.Config.Client(oauth2.NoContext, token)
	svc, err := google_api.New(client)
	if err != nil {
		return nil, err
	}

	u, err := svc.Userinfo.Get().Do()
	if err != nil {
		return nil, err
	}

	s := &Session{
		User:  u.Id,
		Email: u.Email,
		Token: token,
	}
	return s, nil
}
