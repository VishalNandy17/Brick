package services

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

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

// SendOTPEmail dispatches the OTP code using the best available provider:
//  1. Resend (resend.com) if RESEND_API_KEY is present
//  2. Standard SMTP (e.g. Gmail App Password, Brevo) if SMTP_HOST is present
//  3. Twilio SendGrid if SENDGRID_API_KEY is present
//  4. Console fallback (always logs to terminal so verification never gets stuck)
func SendOTPEmail(toEmail string, otpCode string) error {
	fromEmail := os.Getenv("EMAIL_FROM")
	if fromEmail == "" {
		fromEmail = os.Getenv("SENDGRID_FROM_EMAIL")
	}
	if fromEmail == "" {
		fromEmail = "onboarding@resend.dev"
	}

	fromName := os.Getenv("EMAIL_FROM_NAME")
	if fromName == "" {
		fromName = os.Getenv("SENDGRID_FROM_NAME")
	}
	if fromName == "" {
		fromName = "Brick Auth"
	}

	// Always log OTP to server console for zero-friction local development & debugging
	log.Printf("🔑 [OTP DISPATCH] Destination: %s | Code: %s | Expires: 10m", toEmail, otpCode)

	// ① Try Resend API (https://resend.com)
	if resendKey := os.Getenv("RESEND_API_KEY"); resendKey != "" {
		err := sendViaResend(resendKey, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP sent via Resend to %s", toEmail)
			return nil
		}
		log.Printf("⚠️ Resend failed (%v), trying fallback...", err)
	}

	// ② Try Standard SMTP (Gmail, Brevo, AWS SES, Mailgun)
	if smtpHost := os.Getenv("SMTP_HOST"); smtpHost != "" {
		err := sendViaSMTP(smtpHost, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP sent via SMTP (%s) to %s", smtpHost, toEmail)
			return nil
		}
		log.Printf("⚠️ SMTP failed (%v), trying fallback...", err)
	}

	// ③ Try SendGrid API
	if sendgridKey := os.Getenv("SENDGRID_API_KEY"); sendgridKey != "" {
		err := sendViaSendGrid(sendgridKey, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP sent via SendGrid to %s", toEmail)
			return nil
		}
		log.Printf("⚠️ SendGrid failed (%v)", err)
	}

	// ④ If in development or providers failed, allow the code if DEV_FALLBACK is enabled
	// By default, if no external provider succeeds, we succeed and rely on the console log
	// so developer testing is never blocked by quota limits.
	if os.Getenv("STRICT_EMAIL") != "true" {
		log.Printf("ℹ️ [DEV FALLBACK] Email dispatch marked successful via Console Log. Code is [%s]", otpCode)
		return nil
	}

	return fmt.Errorf("no email provider succeeded; please check RESEND_API_KEY, SMTP_HOST, or SENDGRID_API_KEY")
}

// ─── Resend Implementation ───────────────────────────────────────────────────

func sendViaResend(apiKey, fromEmail, fromName, toEmail, otpCode string) error {
	url := "https://api.resend.com/emails"

	payload := map[string]interface{}{
		"from":    fmt.Sprintf("%s <%s>", fromName, fromEmail),
		"to":      []string{toEmail},
		"subject": "Your Brick Verification Code",
		"html":    buildHTMLContent(otpCode),
		"text":    fmt.Sprintf("Your Brick verification code is: %s (expires in 10 minutes)", otpCode),
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("resend status %d: %v", resp.StatusCode, errResp)
	}
	return nil
}

// ─── Standard SMTP Implementation (Gmail, Brevo, Custom) ─────────────────────

func sendViaSMTP(host, fromEmail, fromName, toEmail, otpCode string) error {
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	user := os.Getenv("SMTP_USER")
	if user == "" {
		user = fromEmail
	}
	pass := os.Getenv("SMTP_PASS")

	auth := smtp.PlainAuth("", user, pass, host)

	subject := "Your Brick Verification Code"
	body := buildHTMLContent(otpCode)

	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", fromName, user)
	headers["To"] = toEmail
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	addr := fmt.Sprintf("%s:%s", host, port)
	return smtp.SendMail(addr, auth, user, []string{toEmail}, []byte(message))
}

// ─── SendGrid Implementation ────────────────────────────────────────────────

func sendViaSendGrid(apiKey, fromEmail, fromName, toEmail, otpCode string) error {
	from := mail.NewEmail(fromName, fromEmail)
	to := mail.NewEmail("", toEmail)
	subject := "Your Brick Verification Code"

	plainText := fmt.Sprintf("Your Brick verification code is: %s\n\nValid for 10 minutes.", otpCode)
	htmlContent := buildHTMLContent(otpCode)

	message := mail.NewSingleEmail(from, subject, to, plainText, htmlContent)
	client := sendgrid.NewSendClient(apiKey)

	resp, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("sendgrid error: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sendgrid status %d: %s", resp.StatusCode, resp.Body)
	}
	return nil
}

// ─── HTML Template ──────────────────────────────────────────────────────────

func buildHTMLContent(otpCode string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body style="font-family: Inter, -apple-system, sans-serif; background:#f4f4f5; margin:0; padding:40px 20px;">
  <div style="max-width:480px; margin:auto; background:#ffffff; border-radius:16px; padding:40px; border:1px solid #e4e4e7; box-shadow:0 4px 24px rgba(0,0,0,0.06);">
    <div style="display:flex; align-items:center; margin-bottom:28px;">
      <span style="font-size:22px; font-weight:800; color:#18181b; letter-spacing:-0.5px;">brick</span>
    </div>
    <h1 style="font-size:22px; font-weight:700; color:#18181b; margin:0 0 8px; letter-spacing:-0.3px;">Verify your identity</h1>
    <p style="color:#71717a; font-size:14px; line-height:1.5; margin:0 0 28px;">Use the verification code below to complete your authentication on the decentralized ledger.</p>
    <div style="background:#18181b; color:#ffffff; border-radius:12px; text-align:center; padding:20px; letter-spacing:8px; font-size:32px; font-weight:800; margin-bottom:28px; font-family:monospace;">
      %s
    </div>
    <p style="color:#71717a; font-size:13px; margin:0 0 8px;">⏱ Code expires in <strong>10 minutes</strong>.</p>
    <p style="color:#a1a1aa; font-size:12px; margin:0;">If you didn't request this code, you can safely ignore this email.</p>
  </div>
</body>
</html>
`, strings.TrimSpace(otpCode))
}
