//Refrences:
//1. http://www.inanzzz.com/index.php/post/kdl9/creating-and-validating-a-jwt-rsa-token-in-golang
//2. https://golangbyexample.com/cookies-golang/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type JWT struct {
	privateKey []byte
	publicKey  []byte
}

func NewJWT(privateKey []byte, publicKey []byte) JWT {
	return JWT{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// createToken
func (j JWT) createToken(username string) (tokenStr string, err error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		fmt.Println("Parse Private key went wrong")
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	claims := make(jwt.MapClaims)

	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	claims["sub"] = username

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)

	if err != nil {
		fmt.Println("Create went bad")
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

//Create JWT and send it to client by cookie
func auth(w http.ResponseWriter, req *http.Request) {

	//fmt.Println(publicKey)
	prvKey, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatalln(err)
	}
	pubKey, err := ioutil.ReadFile("id_rsa.pub")
	if err != nil {
		log.Fatalln(err)
	}

	jwtToken := NewJWT(prvKey, pubKey)

	username := strings.Split(req.URL.Path, "/")[2]
	tok, err := jwtToken.createToken(username)
	if err != nil {
		log.Println("Create went wrong")
		log.Println(err.Error())
	}

	// Declare the expiration time of the token
	// here, we have kept it as 24 hours
	expirationTime := time.Now().Add(time.Hour * 24)

	cookie := &http.Cookie{
		Name:     "token",
		Value:    tok,
		HttpOnly: true, //Prevent being access by client JS,
		Path:     "/",  //Visible to all paths???
		Expires:  expirationTime,
	}

	http.SetCookie(w, cookie)
	w.WriteHeader(200)
	w.Write([]byte("Doc Get Successful"))
}

//Validate JWT
func (j JWT) Validate(token string) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return "", fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["sub"], nil
}

//Verify JWT within the cookie
func verify(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Cookies in API Call:")
	tokenCookie, err := req.Cookie("token")
	if err != nil {
		log.Fatalf("Error occured while reading cookie")
	}
	fmt.Println("\nPrinting cookie with name as token")
	fmt.Println(tokenCookie.Expires)

	prvKey, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatalln(err)
	}
	pubKey, err := ioutil.ReadFile("id_rsa.pub")
	if err != nil {
		log.Fatalln(err)
	}

	jwtToken := NewJWT(prvKey, pubKey)

	content, err := jwtToken.Validate(tokenCookie.Value)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("CONTENT:", content)

}

func main() {
	http.HandleFunc("/auth/", auth)
	http.HandleFunc("/verify", verify)
	http.ListenAndServe(":8090", nil)
}
