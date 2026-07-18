//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

func main() {
	// Load .env from parent directory
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("Note: No .env file found or couldn't load it:", err)
	}

	apiKey := os.Getenv("SENDGRID_API_KEY")
	fromEmail := os.Getenv("SENDGRID_FROM_EMAIL")
	fromName := os.Getenv("SENDGRID_FROM_NAME")

	if apiKey == "" {
		log.Fatal("SENDGRID_API_KEY is empty")
	}
	if fromEmail == "" {
		log.Fatal("SENDGRID_FROM_EMAIL is empty")
	}
	if fromName == "" {
		fromName = "Brick Test"
	}

	fmt.Printf("Using API Key: %s...\n", apiKey[:10])
	fmt.Printf("Sending From: %s <%s>\n", fromName, fromEmail)

	toEmail := "nandyvishal17@gmail.com" // User's email from screenshot
	toName := "Vishal Nandy"

	from := mail.NewEmail(fromName, fromEmail)
	subject := "Brick - Test Email Connection"
	to := mail.NewEmail(toName, toEmail)
	plainTextContent := "This is a test email to verify SendGrid connection."
	htmlContent := "<strong>This is a test email to verify SendGrid connection.</strong>"
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)

	client := sendgrid.NewSendClient(apiKey)
	response, err := client.Send(message)
	
	if err != nil {
		log.Fatalf("❌ Error sending email: %v", err)
	}

	fmt.Printf("✅ Status Code: %d\n", response.StatusCode)
	fmt.Printf("Response Body: %s\n", response.Body)
	fmt.Printf("Response Headers: %v\n", response.Headers)

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		fmt.Println("🎉 Email sent successfully!")
	} else {
		fmt.Println("❌ SendGrid rejected the email.")
	}
}
