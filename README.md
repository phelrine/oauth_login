# oauth_login

Login utility with OAuth2 for golang.

## Usage

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/najeira/oauth_login"
)

func main() {
	// setup OAuth2 provider
	provider := oauth_login.NewGoogleProvider(
		"your client id",
		"your client secret",
		"http://example.com/callback")

	// setup cookie store
	cookie := oauth_login.NewCookie("your cookie secret")

	// create OAuth2 object
	auther := oauth_login.New(provider, cookie)

	// OAuth2
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, err := auther.Authenticate(w, r)
		if err != nil {
			// invalid cookie or something wrong
			auther.Logout(w, r) // remove invalid cookie
			w.WriteHeader(500)
			fmt.Fprintf(w, "authenticate error %s", err)
			return
		}
		
		if session == nil {
			// request is not logged in if session is nil
			auther.Redirect(w, r) // redirect to provider
			return
		}
		
		// you can use session here
		fmt.Fprintf(w, "Hello, %s", session.Email)
	})

	// OAuth2 callback
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		session, err := auther.Callback(w, r)
		if err != nil {
			// something wrong
			w.WriteHeader(500)
			fmt.Fprintf(w, "callback error %s", err)
			return
		}
		
		// session is exists and stored in cookie
		log.Printf("email is %s", session.Email)
		
		// get the uri of before OAuth2 steps and redirect
		uri := auther.RequestURI()
		http.Redirect(w, r, uri, http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)
}
```
