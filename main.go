package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/gorilla/mux"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

const (
	privateKeyPath = "app.rsa"
	pubKeyPath     = "app.rsa.pub"
)

var (
	verifyKey, signKey []byte
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Text string `json:"text"`
}

type Token struct {
	Token string `json:"token"`
}

type UserInfo struct {
	Name string
	Role string
}

func (uinf UserInfo) GetUserInfoName() string {
	return uinf.Name
}

func init() {
	var err error

	signKey, err = ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	verifyKey, err = ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error in request body")
		return
	}
	fmt.Print(user)
	if user.Username != "hello" || user.Password != "dunia" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Wrong info")
		return
	}

	t := jwt.New(jwt.GetSigningMethod("RS256"))
	claims := make(jwt.MapClaims)
	claims["iss"] = "admin"
	usrinf := UserInfo{user.Username, "Member"}
	claims["CustomUserInfo"] = usrinf

	claims["exp"] = time.Now().Add(time.Minute * 20).Unix()

	t.Claims = claims

	keyParsed, err := jwt.ParseRSAPrivateKeyFromPEM(signKey)
	if err != nil {
		fmt.Errorf("error parsing RSA private key: %v\n", err)
		return
	}

	tokenString, err := t.SignedString(keyParsed)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	response := Token{tokenString}
	jsonResponse(response, w)

}

func jsonResponse(response interface{}, w http.ResponseWriter) {
	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)

}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// validate the token
	token, err := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		// since we only use one private key to sign the tokens,
		// we also only use its public counter part to verify
		keyParsed, err := jwt.ParseRSAPublicKeyFromPEM(verifyKey)
		if err != nil {
			fmt.Errorf("error parsing RSA private key: %v\n", err)
			return nil, err
		}

		return keyParsed, nil
	})
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError: // something was wrong during the validation
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Token Expired, get a new one.")
				return
			default:
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "Error while Parsing Token!")
				log.Printf("ValidationError error: %+v\n", vErr.Errors)
				return
			}
		default: // something else went wrong
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error while Parsing Token!")
			log.Printf("Token parse error: %v\n", err)
			return
		}
	}

	if token.Valid {
		claims := token.Claims.(jwt.MapClaims)
		sub, hell := claims["CustomUserInfo"].(map[string]interface{})
		ha := reflect.ValueOf(sub)

		for k, v := range sub {
			fmt.Printf("Key: %s Value: %s\n", k, v)
		}

		response := Response{"Authorized to the system username: " + sub["Name"].(string) + " role: " + sub["Role"].(string)}
		log.Printf("User data %v %v", ha, hell)
		jsonResponse(response, w)
	} else {
		response := Response{"Invalid token"}
		jsonResponse(response, w)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/auth", authHandler).Methods("POST")

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	log.Println("Listening")
	server.ListenAndServe()
}
