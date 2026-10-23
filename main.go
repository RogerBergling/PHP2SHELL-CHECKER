package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"
)

func main() {
	port := flag.Int("port", 0, "lokal port (0 = slumpmässig ledig port)")
	noBrowser := flag.Bool("no-browser", false, "öppna inte webbläsaren automatiskt")
	showVersion := flag.Bool("version", false, "visa version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("PHP2Shell Checker %s\n", appVersion)
		return
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fatalNotify("PHP2Shell Checker", "Kunde inte starta den lokala servern:\n\n"+err.Error())
		return
	}

	app := NewApp()
	url := "http://" + listener.Addr().String() + "/"
	fmt.Printf("PHP2Shell Checker %s\n", appVersion)
	fmt.Printf("Öppna %s om webbläsaren inte startar automatiskt.\n", url)
	fmt.Println("Stäng av med knappen \"Stäng av\" i gränssnittet eller med Ctrl+C.")

	if !*noBrowser {
		go openBrowser(url)
	}

	server := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		select {
		case <-app.Shutdown():
		case <-stop:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fatalNotify("PHP2Shell Checker", "Servern stannade oväntat:\n\n"+err.Error())
	}
}

func openBrowser(target string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return
	}
	go func() { _ = command.Wait() }()
}
