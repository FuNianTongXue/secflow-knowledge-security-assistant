package vulnerable

import (
	"net/http"
	"os/exec"
)

func RunShell(writer http.ResponseWriter, request *http.Request) {
	command := request.FormValue("command")
	_ = exec.Command("sh", "-c", command).Run()
}
