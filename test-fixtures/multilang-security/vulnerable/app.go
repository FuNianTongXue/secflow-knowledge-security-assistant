package vulnerable

import (
	"net/http"
	"os/exec"
)

func RunCommand(writer http.ResponseWriter, request *http.Request) {
	command := request.URL.Query().Get("command")
	_ = exec.Command(command).Run()
}
