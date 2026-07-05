package claimer

import (
	"errors"
	"fmt"
	"time"

	"github.com/Kqzz/MCsniperGO/log"
	"github.com/Kqzz/MCsniperGO/pkg/mc"
	"github.com/gookit/color"
)

type StatsStore struct {
	Total           int
	TooManyRequests int
	Duplicate       int
	NotAllowed      int
	Success         int
	StartTime       time.Time
}

const (
	authOffset = time.Hour * 8
	spread     = 0
)

var Stats StatsStore

func ResetStats() {
	Stats = StatsStore{}
}

func ClaimWithinRange(username string, dropRange mc.DropRange, accounts []*mc.MCaccount, proxies []string) error {

	fmt.Print("\n")
	log.Log("info", "sniping %s at %s", username, dropRange.Start.Format("02 Jan 06 15:04 MST"))
	emitEvent("info", fmt.Sprintf("sniping %s at %s", username, dropRange.Start.Format("02 Jan 06 15:04 MST")))

	for {
		if time.Until(dropRange.Start) > authOffset {
			color.Printf("\r[<fg=blue>*</>] authing in %v    ", time.Until(dropRange.Start.Add(-time.Hour*8)).Round(time.Second))
			time.Sleep(time.Second * 1)
		} else {
			color.Printf("\r[<fg=blue>*</>] starting auth...\n\n")
			emitEvent("info", "starting authentication...")
			break
		}
	}

	usableAccounts := []*mc.MCaccount{}

	for i, account := range accounts {

		if account.Bearer != "" {
			usableAccounts = append(usableAccounts, account)
			continue
		}

		if i != 0 {
			time.Sleep(time.Second * 21)
		}

		authErr := account.MicrosoftAuthenticate("")
		if authErr != nil {
			msg := fmt.Sprintf("failed to authenticate %v: %v", account.Email, authErr)
			log.Log("err", "failed to authenticate %v: %v", account.Email, authErr)
			emitEvent("err", msg)
			time.Sleep(time.Second * 21)
			continue
		} else {
			msg := fmt.Sprintf("authenticated %s", account.Email)
			log.Log("success", "authenticated %s", account.Email)
			emitEvent("success", msg)
		}

		time.Sleep(time.Millisecond * 500)
		if account.Type == mc.MsGp {
			licenseErr := account.License()
			if licenseErr != nil {
				msg := fmt.Sprintf("failed to license %v: %v", account.Email, licenseErr)
				log.Log("err", "failed to license %v: %v", account.Email, licenseErr)
				emitEvent("err", msg)
				continue
			}
			usableAccounts = append(usableAccounts, account)
		}

		if account.Type == mc.Ms {
			_, checkErr := account.NameChangeInfo()
			if checkErr != nil {
				msg := fmt.Sprintf("failed to confirm name change for %v: %v", account.Email, checkErr)
				log.Log("err", "failed to confirm name change for %v: %v", account.Email, checkErr)
				emitEvent("err", msg)
				continue
			}
			usableAccounts = append(usableAccounts, account)
			continue
		}

		if account.Type == mc.MsPr {
			_, checkErr := account.HasGcApplied()

			if checkErr != nil {
				msg := fmt.Sprintf("failed to confirm gift code claim for %v: %v", account.Email, checkErr)
				log.Log("err", "failed to confirm gift code claim for %v: %v", account.Email, checkErr)
				emitEvent("err", msg)
				continue
			}

			usableAccounts = append(usableAccounts, account)
		}

	}

	if len(usableAccounts) == 0 {
		return errors.New("no accounts successfully authenticated")
	} else {
		msg := fmt.Sprintf("authenticated %d account(s)", len(usableAccounts))
		log.Log("success", "authenticated %d account(s)\n", len(usableAccounts))
		emitEvent("success", msg)
	}

	for {
		if time.Until(dropRange.Start) > time.Second*20 {
			color.Printf("\r[<fg=blue>*</>] sniping in %v    ", time.Until(dropRange.Start).Round(time.Second))
			time.Sleep(time.Second * 1)
		} else {
			color.Printf("\r[<fg=blue>*</>] starting snipe...\n")
			emitEvent("info", "starting snipe...")
			break
		}
	}

	snipe := &Claim{
		Username:  username,
		Accounts:  usableAccounts,
		DropRange: dropRange,
		Running:   true,
		Proxies:   proxies,
	}

	snipe.runClaim()

	return nil
}
