package safe

import (
	"net/http"
	"os/exec"
)

func RunCommand(writer http.ResponseWriter, request *http.Request) {
	value := request.URL.Query().Get("value")
	_ = exec.Command("/usr/bin/printf", "%s", value).Run()
}
