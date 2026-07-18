package services

import (
	"strings"
)

// disposableDomains is a comprehensive blocklist of known junk/disposable email providers
var disposableDomains = map[string]struct{}{
	"mailinator.com":       {},
	"guerrillamail.com":    {},
	"guerrillamail.net":    {},
	"guerrillamail.org":    {},
	"guerrillamail.biz":    {},
	"guerrillamail.de":     {},
	"guerrillamailblock.com": {},
	"sharklasers.com":      {},
	"grr.la":               {},
	"spam4.me":             {},
	"10minutemail.com":     {},
	"10minutemail.net":     {},
	"10minutemail.org":     {},
	"10minutemail.co.uk":   {},
	"trashmail.com":        {},
	"trashmail.me":         {},
	"trashmail.net":        {},
	"trashmail.at":         {},
	"trashmail.xyz":        {},
	"trashmail.fr":         {},
	"trashmail.io":         {},
	"yopmail.com":          {},
	"yopmail.fr":           {},
	"cool.fr.nf":           {},
	"jetable.fr.nf":        {},
	"nospam.ze.tc":         {},
	"nomail.xl.cx":         {},
	"mega.zik.dj":          {},
	"speed.1s.fr":          {},
	"courriel.fr.nf":       {},
	"moncourrier.fr.nf":    {},
	"monemail.fr.nf":       {},
	"monmail.fr.nf":        {},
	"fakeinbox.com":        {},
	"dispostable.com":      {},
	"throwam.com":          {},
	"throwam.net":          {},
	"throwaway.email":      {},
	"spamgourmet.com":      {},
	"spamgourmet.net":      {},
	"spamgourmet.org":      {},
	"incognitomail.org":    {},
	"mailnull.com":         {},
	"spammotel.com":        {},
	"binkmail.com":         {},
	"bobmail.info":         {},
	"chammy.info":          {},
	"devnullmail.com":      {},
	"mailin8r.com":         {},
	"mailme.lv":            {},
	"mailnew.com":          {},
	"mailsiphon.com":       {},
	"nwldx.com":            {},
	"safetypost.de":        {},
	"sendspamhere.com":     {},
	"shortmail.net":        {},
	"spamherelots.com":     {},
	"spamhereplease.com":   {},
	"spamthisplease.com":   {},
	"tempomail.fr":         {},
	"tempinbox.com":        {},
	"tempr.email":          {},
	"discard.email":        {},
	"discardmail.com":      {},
	"discardmail.de":       {},
	"einrot.com":           {},
	"filzmail.com":         {},
	"getairmail.com":       {},
	"haltospam.com":        {},
	"jetable.com":          {},
	"jetable.net":          {},
	"jetable.org":          {},
	"killmail.com":         {},
	"killmail.net":         {},
	"lazyinbox.com":        {},
	"letthemeatspam.com":   {},
	"lookugly.com":         {},
	"mailblocks.com":       {},
	"mailexpire.com":       {},
	"mailmoat.com":         {},
	"mailscrap.com":        {},
	"mailshell.com":        {},
	"mailslite.com":        {},
	"mailseal.de":          {},
	"mailzilla.org":        {},
	"mayn.de":              {},
	"mt2009.com":           {},
	"mt2014.com":           {},
	"mt2015.com":           {},
	"nospamfor.us":         {},
	"nospamthanks.info":    {},
	"notsharingmy.info":    {},
	"notmailinator.com":    {},
	"ownmail.net":          {},
	"pecinan.com":          {},
	"pookmail.com":         {},
	"privatdemail.net":     {},
	"proxymail.eu":         {},
	"rklips.com":           {},
	"rppkn.com":            {},
	"smellfear.com":        {},
	"spamfree24.org":       {},
	"spaminmotion.com":     {},
	"spamkill.info":        {},
	"spamoff.de":           {},
	"suremail.info":        {},
	"venompen.com":         {},
	"webemail.me":          {},
	"weg-werf-email.de":    {},
	"wegwerf-email.at":     {},
	"wegwerfmail.de":       {},
	"wegwerfmail.net":      {},
	"wegwerfmail.org":      {},
	"wh4f.org":             {},
	"whyspam.me":           {},
	"willselfdestruct.com": {},
	"wuzupmail.net":        {},
	"xagloo.com":           {},
	"xemaps.com":           {},
	"xents.com":            {},
	"xmaily.com":           {},
	"xoxy.net":             {},
	"yapped.net":           {},
	"yogamaven.com":        {},
	"yroid.com":            {},
	"z1p.biz":              {},
	"zehnminutenmail.de":   {},
	"zippymail.info":       {},
	"zoemail.net":          {},
	"zoemail.org":          {},
}

// IsDisposableEmail checks if the email domain is in the blocklist
func IsDisposableEmail(email string) bool {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return true // malformed email
	}
	domain := parts[1]
	_, blocked := disposableDomains[domain]
	return blocked
}

// IsValidEmailFormat checks basic email format
func IsValidEmailFormat(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	local := parts[0]
	domain := parts[1]
	if len(local) == 0 || len(domain) < 3 {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// ValidateEmail validates format and rejects disposable domains
func ValidateEmail(email string) (bool, string) {
	if !IsValidEmailFormat(email) {
		return false, "Invalid email format"
	}
	if IsDisposableEmail(email) {
		return false, "Temporary or disposable email addresses are not allowed. Please use your real email."
	}
	return true, ""
}
