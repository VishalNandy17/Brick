package services

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// EmailResult tracks whether the email was physically dispatched to an external inbox
type EmailResult struct {
	Delivered bool
	Provider  string
}

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
//  1. Resend API (HTTPS port 443 — reliable across cloud hosts like Render)
//  2. Standard SMTP with 3s dial timeout (so blocked ports never hang requests)
//  3. Twilio SendGrid
//  4. Console fallback (always logs code to stdout so user/dev is never blocked)
func SendOTPEmail(toEmail string, otpCode string) (EmailResult, error) {
	fromEmail := os.Getenv("EMAIL_FROM")
	if fromEmail == "" {
		fromEmail = os.Getenv("SENDGRID_FROM_EMAIL")
	}
	if fromEmail == "" {
		fromEmail = "auth@trybrick.dev"
	}

	fromName := os.Getenv("EMAIL_FROM_NAME")
	if fromName == "" {
		fromName = os.Getenv("SENDGRID_FROM_NAME")
	}
	if fromName == "" {
		fromName = "Brick Auth"
	}

	// Always log OTP to server console for zero-friction debugging
	log.Printf("🔑 [OTP DISPATCH] Destination: %s | Code: %s | Expires: 10m", toEmail, otpCode)

	// 1️⃣ Try Resend API (HTTPS port 443)
	if resendKey := os.Getenv("RESEND_API_KEY"); resendKey != "" {
		err := sendViaResend(resendKey, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP successfully sent via Resend to %s", toEmail)
			return EmailResult{Delivered: true, Provider: "resend"}, nil
		}
		log.Printf("⚠️ Resend failed (%v), trying next provider...", err)
	}

	// 2️⃣ Try Standard SMTP (with 3-second dial timeout)
	if smtpHost := os.Getenv("SMTP_HOST"); smtpHost != "" {
		err := sendViaSMTP(smtpHost, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP sent via SMTP (%s) to %s", smtpHost, toEmail)
			return EmailResult{Delivered: true, Provider: "smtp"}, nil
		}
		log.Printf("⚠️ SMTP failed or blocked (%v), trying fallback...", err)
	}

	// 3️⃣ Try SendGrid API
	if sendgridKey := os.Getenv("SENDGRID_API_KEY"); sendgridKey != "" {
		err := sendViaSendGrid(sendgridKey, fromEmail, fromName, toEmail, otpCode)
		if err == nil {
			log.Printf("✅ OTP sent via SendGrid to %s", toEmail)
			return EmailResult{Delivered: true, Provider: "sendgrid"}, nil
		}
		log.Printf("⚠️ SendGrid failed (%v)", err)
	}

	// 4️⃣ Fallback: Allow code dispatch and log to console
	log.Printf("🛡️ [DEV/DEMO FALLBACK] Email marked processed. Verification code for [%s] is: %s", toEmail, otpCode)
	return EmailResult{Delivered: false, Provider: "console_fallback"}, nil
}

// ─── Resend Implementation ───────────────────────────────────────────────────

func sendViaResend(apiKey, fromEmail, fromName, toEmail, otpCode string) error {
	url := "https://api.resend.com/emails"

	// Default to verified domain sender: auth@trybrick.dev
	resendFrom := fromEmail
	if resendFrom == "" || strings.HasSuffix(resendFrom, "@gmail.com") || strings.HasSuffix(resendFrom, "@yahoo.com") || strings.HasSuffix(resendFrom, "@outlook.com") {
		resendFrom = "auth@trybrick.dev"
	}

	payload := map[string]interface{}{
		"from":    fmt.Sprintf("%s <%s>", fromName, resendFrom),
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

	client := &http.Client{Timeout: 6 * time.Second}
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

// ─── Standard SMTP Implementation (with 3-second dial timeout) ───────────────

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

	addr := fmt.Sprintf("%s:%s", host, port)

	// Dial with 3-second timeout so blocked cloud ports (like Render free tier) abort quickly
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("smtp connection timeout/blocked: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: host}
		if err = client.StartTLS(config); err != nil {
			return err
		}
	}

	if pass != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		if err = client.Auth(auth); err != nil {
			return err
		}
	}

	if err = client.Mail(user); err != nil {
		return err
	}
	if err = client.Rcpt(toEmail); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

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

	if _, err = w.Write([]byte(message)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// ─── SendGrid Implementation ─────────────────────────────────────────────────

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

// ─── HTML Template ───────────────────────────────────────────────────────────

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
    <p style="color:#71717a; font-size:13px; margin:0 0 8px;">⏱️ Code expires in <strong>10 minutes</strong>.</p>
    <p style="color:#a1a1aa; font-size:12px; margin:0;">If you didn't request this code, you can safely ignore this email.</p>
  </div>
</body>
</html>
`, strings.TrimSpace(otpCode))
}
