package safe

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

func OpenSafeFile(writer http.ResponseWriter, request *http.Request, root string) {
	name := filepath.Base(request.FormValue("name"))
	_, _ = os.Open(filepath.Join(root, name))
}

func BuildSafeRequest(writer http.ResponseWriter, request *http.Request, baseURL string) {
	challenge := url.QueryEscape(request.FormValue("challenge"))
	_, _ = http.NewRequest(http.MethodGet, baseURL+"?challenge="+challenge, nil)
}
