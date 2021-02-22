package main

import (
	"auth/controller"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()
	fmt.Println("Server started on PORT: 8000")
	r.HandleFunc("/register", controller.RegisterHandler).
		Methods("POST")
	r.HandleFunc("/login", controller.SignInHandler).
		Methods("POST")
	r.HandleFunc("/refresh", controller.UpdateJWT).
		Methods("GET")
	log.Fatal(http.ListenAndServe(":8000", r))
}
