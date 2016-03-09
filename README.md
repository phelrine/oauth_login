# oauth2

## Usage

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/najeira/oauth2"
)

func main() {
	provider := oauth2.NewGoogleProvider(
		"clientID", "clientSecret", "http://example.com/oauth2callback")
	cookie := oauth2.NewCookie("cookieSecret")
	auther := oauth2.New(provider, cookie)

	http.HandleFunc("/oauth2callback", auther.Callback)

	http.HandleFunc("/", func handler(w http.ResponseWriter, r *http.Request) {
		session, _ := auther.Authenticate(w, r)
		if session != nil {
			fmt.Fprintf(w, "Hello, %s", session.Email)
		} else {
			auther.Redirect(w, r)
		}
	})

	http.ListenAndServe(":8080", nil)
}
```
