package main

import (
	"fmt"
	"log"
	"net/mail"
	"github.com/mcnijman/go-emailaddress"
	"github.com/go-resty/resty/v2"
	"encoding/json"
)

// https://www.ipqualityscore.com/api/json/email/token/abc@xyz.com

type IpQualityScoreResponse struct {
	TimedOut           bool   `json:"timed_out"`
	Disposable         bool   `json:"disposable"`
	FirstName          string `json:"first_name"`
	Deliverability     string `json:"deliverability"`
	SMTPScore          int    `json:"smtp_score"`
	OverallScore       int    `json:"overall_score"`
	CatchAll           bool   `json:"catch_all"`
	Generic            bool   `json:"generic"`
	Common             bool   `json:"common"`
	DNSValid           bool   `json:"dns_valid"`
	Honeypot           bool   `json:"honeypot"`
	FrequentComplainer bool   `json:"frequent_complainer"`
	Suspect            bool   `json:"suspect"`
	RecentAbuse        bool   `json:"recent_abuse"`
	Leaked             bool   `json:"leaked"`
	SuggestedDomain    string `json:"suggested_domain"`
	FirstSeen          struct {
		Human     string `json:"human"`
		Timestamp int    `json:"timestamp"`
		Iso       string `json:"iso"`
	} `json:"first_seen"`
	DomainAge struct {
		Human     string `json:"human"`
		Timestamp int    `json:"timestamp"`
		Iso       string `json:"iso"`
	} `json:"domain_age"`
	Valid          bool   `json:"valid"`
	FraudScore     int    `json:"fraud_score"`
	Success        bool   `json:"success"`
	SpamTrapScore  string `json:"spam_trap_score"`
	SanitizedEmail string `json:"sanitized_email"`
	RequestID      string `json:"request_id"`
}

var ipqualityscore_email_token = "token"

func IsEmailVerified(emailAddress string) bool {
	// Create a Resty Client
	client := resty.New()

	resp, err := client.R().
		SetHeader("Accept", "application/json").
		Get("https://www.ipqualityscore.com/api/json/email/"+ipqualityscore_email_token+"/" + emailAddress)

	if err != nil {
		/* Manual our verifications */
		return true
	}

	var verifyResponse IpQualityScoreResponse
	json.Unmarshal(resp.Body(), &verifyResponse)
	if verifyResponse.FraudScore >= 80 {
		return false
	}

	return true
}


func main() {
	e, err := mail.ParseAddress("Alice <alice@example.com>")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(e.Name, e.Address)


	email, err := emailaddress.Parse("foo@bar.com")
	if err != nil {
		fmt.Println("invalid email")
	}

	fmt.Println(email.LocalPart) // foo
	fmt.Println(email.Domain) // bar.com
	fmt.Println(email) // foo@bar.com
	fmt.Println(email.String()) // foo@bar.com

	fmt.Println(IsEmailVerified("thomas.rosenberg@ismailgul.net"))
}

