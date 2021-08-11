package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID          string `json:"id" bson:"id"`
	MailAddress string `json:"mail" bson:"mail"`
	UserName    string `json:"username" bson:"username"`
	Password    []byte `json:"password" bson:"password"`
}

type Session struct {
	SessionToken string `json:"sessionToken" bson:"sessionToken"`
	UserID       string `json:"userID" bson:"userID"`
	UniqueIP	 string `json:"ip" bson:"ip"`
}

const usersDatabase = "users"

func main() {
	server := fiber.New()
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(os.Getenv("MONGO")))
	if err != nil {
		panic(err)
	}

	err = mongoClient.Connect(context.TODO())
	if err != nil {
		panic(err)
	}

	fmt.Println("Mongo Atlas successfully connected...")
	fmt.Println("Initializing Server...")

	setSettings(server)
	buildRouting(server, mongoClient)

	server.Listen(":8080")
}

func v1(router fiber.Router, mongoClient *mongo.Client) {
	apiVersion := 1
	usersSessionTokens := make(map[string]Session)
	authCookieName := "_authSession_v1"

	router.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(buildAPIResponse(false, "ok", fiber.Map{}, apiVersion))
	})

	router.Get("/authentication", func(c *fiber.Ctx) error {
		return c.JSON(buildAPIResponse(false, "api authentication are working", fiber.Map{}, apiVersion))
	})

	router.Post("/authentication/signup", func(c *fiber.Ctx) error {
		mail := strings.ToLower(c.Query("user-mail"))
		username := strings.ToLower(c.Query("user-username"))
		password := c.Query("user-password")
		confirmedPassword := c.Query("user-password-confirmation")
		acceptedTermsAndPrivacy := c.Query("user-terms-privacy")

		userData := []string{mail, username, password, confirmedPassword,acceptedTermsAndPrivacy}

		for _, data := range userData {
			if len(data) <= 0 {
				return c.JSON(serverError(c, "not_data", "you have to provide all information for create an account"))
			}
		}

		// Mail

		mailRegexp := regexp.MustCompile("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")
		if !mailRegexp.MatchString(mail) {
			return c.JSON(serverError(c, "invalid_mail", map[string]interface{}{
				"mail": "misspelled mail, try to correct it",
			}))
		}

		userWithThatMail := &User{}
		err := mongoClient.Database(usersDatabase).Collection("data").FindOne(context.TODO(), bson.D{{"mail", mail}}).Decode(userWithThatMail)
		if err != nil && !mongoUnknown(err.Error()) {
			return c.JSON(serverError(c, "database_error", err.Error()))
		}

		if len(userWithThatMail.ID) >= 1 {
			return c.JSON(serverError(c, "used_mail", map[string]interface{}{
				"mail": "that mail is already used",
			}))
		}

		// Username

		if len(username) < 3 {
			return c.JSON(serverError(c, "short_username", "username need to have 3 letters or higher"))
		}

		if len(username) > 25 {
			return c.JSON(serverError(c, "long_username", "username can only have 25 letters or less"))
		}

		usernameRegexp := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
		if !usernameRegexp.MatchString(username) {
			return c.JSON(serverError(c, "invalid_username", map[string]interface{}{
				"username": "username can only contain letters, numbers and underscores",
			}))
		}

		userWithThatUsername := &User{}
		err = mongoClient.Database(usersDatabase).Collection("data").FindOne(context.TODO(), bson.D{{"username", username}}).Decode(userWithThatUsername)
		if err != nil && !mongoUnknown(err.Error()) {
			return c.JSON(serverError(c, "database_error", err.Error()))
		}

		if len(userWithThatUsername.ID) >= 1 {
			return c.JSON(serverError(c, "used_username", map[string]interface{}{
				"username": "that username is already used",
			}))
		}

		// Pasword

		if len(password) < 5 {
			return c.JSON(serverError(c, "long_password", map[string]interface{}{
				"password": "password need to have minimum 5 letters",
			}))
		}

		if strings.Compare(password, confirmedPassword) != 0 {
			return c.JSON(serverError(c, "not_match_password", map[string]interface{}{
				"password": "password don't match with he confirmation",
			}))
		}

		// Terms And Privacy

		if strings.Compare(acceptedTermsAndPrivacy, "accepted") != 0 {
			return c.JSON(serverError(c, "not_accepted_terms_and_privacy", map[string]interface{}{
				"terms_privacy": "you have to accept the terms of service and privacy",
			}))
		}

		// Hashing the password

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
		if err != nil {
			return c.JSON(serverError(c, "password_issues", map[string]interface{}{
				"password": "issues while trying to encrypting the password",
			}))
		}

		user := &User{
			ID:          fmt.Sprintf("%d", rand.Int63()),
			MailAddress: mail,
			UserName:    strings.ToLower(username),
			Password:    passwordHash,
		}

		_, err = mongoClient.Database(usersDatabase).Collection("data").InsertOne(context.TODO(), user)
		if err != nil {
			return c.JSON(serverError(c, "error", err.Error()))
		}

		c.SendStatus(201)
		return c.JSON(buildAPIResponse(false, "created", user, apiVersion))
	})

	router.Post("/authentication/signin", func(c *fiber.Ctx) error {
		account := c.Query("account-mail-username")
		password := c.Query("account-password")

		if len(account) <= 0 || len(password) <= 0 {
			return c.JSON(serverError(c, "not_provided_credentials", map[string]interface{}{
				"mail_username": "invalid email or username",
				"password":      "invalid password",
			}))
		}

		userAssociated := &User{}
		err := mongoClient.Database(usersDatabase).Collection("data").FindOne(context.TODO(), bson.D{{"username", account}}).Decode(&userAssociated)
		if err != nil {
			fmt.Println(err)
			if mongoUnknown(err.Error()) {
				err = mongoClient.Database(usersDatabase).Collection("data").FindOne(context.TODO(), bson.D{{"mail", account}}).Decode(&userAssociated)

				if err != nil && len(userAssociated.ID) <= 0 {
					return c.JSON(serverError(c, "unknown_account", map[string]interface{}{
						"mail_username": "mail or username not associated to any account",
						"password":      nil,
					}))
				}
			}

			return c.JSON(serverError(c, "database_error", err.Error()))
		}

		if len(userAssociated.ID) <= 0 {
			return c.JSON(serverError(c, "not_provided_credentials", map[string]interface{}{
				"mail_username": "email or username are associated to any account",
				"password":      nil,
			}))
		}

		err = bcrypt.CompareHashAndPassword([]byte(userAssociated.Password), []byte(password))
		if err != nil {
			return c.JSON(serverError(c, "incorrect_password", map[string]interface{}{
				"mail_username": nil,
				"password":      "incorrect password",
			}))
		}

		userSessionData := &Session{}
		userSessionData.SessionToken = generateNewToken(40)
		userSessionData.UserID = userAssociated.ID
		userSessionData.UniqueIP = c.IP()

		usersSessionTokens[userSessionData.SessionToken] = *userSessionData

		c.Cookie(&fiber.Cookie{
			Name:     authCookieName,
			Value:    userSessionData.SessionToken,
			MaxAge:   int(21600),
			SameSite: "Lax",
		})

		return c.JSON(buildAPIResponse(false, "authorized", nil, apiVersion))
	})

	router.Post("/authentication/request/user/data", func(c *fiber.Ctx) error {
		sessionToken := c.Cookies(authCookieName)
		if len(sessionToken) <= 0 {
			return c.JSON(serverError(c, "unknown_cookie", "you have to sign in"))
		}

		sessionData := usersSessionTokens[sessionToken]
		if len(sessionData.UserID) <= 0 {
			return c.JSON(serverError(c, "expired_session", "you session has been expired, please sign in again"))
		}

		account := &User{}
		err := mongoClient.Database(usersDatabase).Collection("data").FindOne(context.TODO(), bson.D{{"id", sessionData.UserID}}).Decode(&account)
		if err != nil {
			if mongoUnknown(err.Error()) {
				return c.JSON(serverError(c, "session_not_linked", "your session not are linked to none account, probably your account has been deleted"))
			}

			return c.JSON(serverError(c, "database_error", err.Error()))
		}

		account.Password = nil
		userSessionData := &Session{}
		userSessionData.SessionToken = generateNewToken(40)
		userSessionData.UserID = account.ID
		userSessionData.UniqueIP = c.IP()

		usersSessionTokens[userSessionData.SessionToken] = *userSessionData

		c.Cookie(&fiber.Cookie{
			Name:     authCookieName,
			Value:    userSessionData.SessionToken,
			MaxAge:   int(21600),
			SameSite: "Lax",
		})

		return c.JSON(buildAPIResponse(false, "authorized", account, apiVersion))
	})
}

func setSettings(server *fiber.App) {
	//server.Use(csrf.New())
	server.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins: clientDomain,
	}))

	server.Use(limiter.New(limiter.Config{
		Max:        300,
		Expiration: time.Hour,
		LimitReached: func(c *fiber.Ctx) error {
			c.SendStatus(429)
			return c.JSON(buildCurrentResponse(true, "too many requests", nil))
		},
	}))
}

func buildRouting(server *fiber.App, mongoClient *mongo.Client) {
	apiRouter := server.Group("/api")
	firstVersionRouter := apiRouter.Group("/v1", func(c *fiber.Ctx) error {
		sessionToken := c.Cookies(authCookieName)
		if len(sessionToken) >= 1 {
			session := usersSessionTokens[sessionToken]
			if len(session.UserID) <= 0 {
				return c.Next()
			}

			userSessionData := &Session{}
			userSessionData.SessionToken = generateNewToken(40)
			userSessionData.UserID = session.UserID
			userSessionData.UniqueIP = c.IP()

			usersSessionTokens[userSessionData.SessionToken] = *userSessionData

			c.Cookie(&fiber.Cookie{
				Name:     authCookieName,
				Value:    userSessionData.SessionToken,
				MaxAge:   int(21600),
			})
		}

		return c.Next()
	})

	v1(firstVersionRouter, mongoClient)
}

func buildAPIResponse(issues bool, message string, data interface{}, version int) fiber.Map {

	code := 0
	if issues {
		code = 1
	}

	return fiber.Map{
		"code":    code,
		"data":    data,
		"message": message,
		"_v":      version,
	}
}

func buildCurrentResponse(issues bool, message string, errors interface{}) fiber.Map {

	code := 0
	if issues {
		code = 1
	}

	return fiber.Map{
		"code":    code,
		"message": message,
		"errors":  errors,
	}
}

func serverError(c *fiber.Ctx, message string, errors interface{}) fiber.Map {
	c.SendStatus(400)
	return buildCurrentResponse(true, message, errors)
}

func mongoUnknown(err string) bool {
	if strings.Compare(err, "mongo: no documents in result") == 0 {
		return true
	} else {
		return false
	}
}

func generateNewToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
