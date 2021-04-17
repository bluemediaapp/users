package main

import (
	"context"
	"github.com/alexedwards/argon2id"
	"github.com/bluemediaapp/models"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
)

var (
	app    = fiber.New()
	client *mongo.Client
	config *Config

	mctx                = context.Background()
	usersCollection     *mongo.Collection
	userLoginCollection *mongo.Collection
)

func main() {
	config = &Config{
		port:     os.Getenv("port"),
		mongoUri: os.Getenv("mongo_uri"),
	}

	app.Post("/login", func(ctx *fiber.Ctx) error {
		userName := ctx.Params("username", "")
		password := ctx.Params("password", "")

		if userName == "" || password == "" {
			return ctx.Status(403).SendString("username or password not provided.")
		}

		login, err := getUserLogin(userName)
		if err != nil {
			return ctx.Status(403).SendString("Invalid username")
		}

		isCorrect, err := argon2id.ComparePasswordAndHash(password, login.Password)
		if err != nil {
			return err
		}

		if !isCorrect {
			return ctx.Status(403).SendString("Invalid password")
		}
		token, err := CreateJWTToken(login.Id)
		if err != nil {
			return err
		}
		return ctx.SendString(token)
	})

	initDb()
	log.Fatal(app.Listen(config.port))
}

func initDb() {
	// Connect mongo
	var err error
	client, err = mongo.NewClient(options.Client().ApplyURI(config.mongoUri))
	if err != nil {
		log.Fatal(err)
	}

	err = client.Connect(mctx)
	if err != nil {
		log.Fatal(err)
	}

	// Setup tables
	db := client.Database("blue")
	usersCollection = db.Collection("users")
	userLoginCollection = db.Collection("users_login")
}

// Db utils
func getUserLogin(userName string) (models.UserLogin, error) {
	query := bson.D{{"_id", userName}}
	rawVideo := userLoginCollection.FindOne(mctx, query)
	var userLogin models.UserLogin
	err := rawVideo.Decode(&userLogin)
	if err != nil {
		return models.UserLogin{}, err
	}
	return userLogin, nil
}
