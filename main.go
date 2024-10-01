package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
}

type Note struct {
	ID      uint `gorm:"primaryKey"`
	UserID  uint
	Content string
}

var DB *gorm.DB

func initialiseDatabase() {
	var err error
	DB, err = gorm.Open(sqlite.Open("./database.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	DB.AutoMigrate(&User{}, &Note{})
}

func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func Encrypt(plaintext string, key string) (string, error) {
	block, err := aes.NewCipher(createHash(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext string, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(createHash(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertextData := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func CreateNote(c *gin.Context) {
	var jsonData struct {
		Username string `json:"username"`
		Note     string `json:"note"`
	}
	if err := c.BindJSON(&jsonData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := DB.Where("username = ?", jsonData.Username).First(&user).Error; err != nil {
		user = User{Username: jsonData.Username}
		DB.Create(&user)
	}

	note := Note{
		UserID:  user.ID,
		Content: jsonData.Note,
	}
	DB.Create(&note)
	c.JSON(http.StatusOK, gin.H{"message": "Note created", "note_id": note.ID})
}

func GetNote(c *gin.Context) {
	noteID := c.Param("id")
	var note Note
	if err := DB.First(&note, noteID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Note not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"note": note.Content})
}

func main() {
	initialiseDatabase()

	r := gin.Default()
	r.POST("/notes", CreateNote)
	r.GET("/notes/:id", GetNote)

	log.Println("Server started on :3827...")
	r.Run(":3827")
}
