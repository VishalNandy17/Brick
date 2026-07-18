package services

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// GenerateOTP creates a cryptographically secure 6-digit code
func GenerateOTP() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	code := fmt.Sprintf("%06d", n%1000000)
	return code, nil
}

// SendOTPEmail dispatches the OTP via Twilio SendGrid
func SendOTPEmail(toEmail string, otpCode string) error {
	apiKey := os.Getenv("SENDGRID_API_KEY")
	fromEmail := os.Getenv("SENDGRID_FROM_EMAIL")
	fromName := os.Getenv("SENDGRID_FROM_NAME")

	if apiKey == "" {
		return fmt.Errorf("SENDGRID_API_KEY not configured")
	}
	if fromEmail == "" {
		fromEmail = "noreply@brickauth.io"
	}
	if fromName == "" {
		fromName = "Brick Auth"
	}

	from := mail.NewEmail(fromName, fromEmail)
	to := mail.NewEmail("", toEmail)
	subject := "Your Brick Verification Code"

	plainText := fmt.Sprintf(
		"Your Brick verification code is: %s\n\nThis code expires in 10 minutes.\n\nIf you did not request this, please ignore this email.",
		otpCode,
	)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body style="font-family: Inter, -apple-system, sans-serif; background:#f5f5f5; margin:0; padding:40px;">
  <div style="max-width:480px; margin:auto; background:#fff; border-radius:12px; padding:40px; box-shadow:0 2px 20px rgba(0,0,0,0.08);">
    <div style="display:flex; align-items:center; margin-bottom:32px;">
      <div style="background:#18181b; color:#fff; border-radius:8px; width:36px; height:36px; display:flex; align-items:center; justify-content:center; font-size:18px; font-weight:800; margin-right:10px;">⬛</div>
      <span style="font-size:20px; font-weight:700; color:#18181b;">brick</span>
    </div>
    <h1 style="font-size:24px; font-weight:700; color:#18181b; margin:0 0 8px;">Verify your email</h1>
    <p style="color:#71717a; font-size:14px; margin:0 0 32px;">Enter this code to verify your identity and access your blockchain account.</p>
    <div style="background:#18181b; color:#fff; border-radius:10px; text-align:center; padding:24px; letter-spacing:10px; font-size:32px; font-weight:800; margin-bottom:32px;">
      %s
    </div>
    <p style="color:#71717a; font-size:13px; margin:0 0 8px;">⏱ This code expires in <strong>10 minutes</strong>.</p>
    <p style="color:#a1a1aa; font-size:12px; margin:0;">If you didn't request this, you can safely ignore this email.</p>
  </div>
</body>
</html>
`, otpCode)

	message := mail.NewSingleEmail(from, subject, to, plainText, htmlContent)
	client := sendgrid.NewSendClient(apiKey)

	resp, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("sendgrid send error: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sendgrid responded with status %d: %s", resp.StatusCode, resp.Body)
	}

	return nil
}
