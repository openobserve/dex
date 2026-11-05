package templates

// o2.go holds the OpenObserve fork's sign-up, password-reset and sign-in page
// additions: the extra templates, their renderers and the query parameters the
// O2 auth pages carry from one step to the next.

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

const (
	tmplSignup        = "signup.html"
	tmplPasswordReset = "password_reset.html"

	// ScreenHintParam carries the sign-up intent from O2 through every dex auth page.
	ScreenHintParam  = "screen_hint"
	ScreenHintSignup = "signup"

	// AccountCreatedParam and LoginHintParam carry a finished sign-up to the password step when auto sign-in is not possible.
	AccountCreatedParam = "account_created"
	LoginHintParam      = "login_hint"
)

// o2RequiredTmpls are the fork's templates; Dex fails at startup without them.
var o2RequiredTmpls = []string{
	tmplSignup,
	tmplPasswordReset,
}

// o2Templates are the fork's parsed templates, embedded in Templates.
type o2Templates struct {
	signupTmpl        *template.Template
	passwordResetTmpl *template.Template
}

// AuthTabs drives the "Sign in | Create account" switch on the chooser and the email step.
type AuthTabs struct {
	SignupMode bool
	SignInURL  template.URL
	SignupURL  template.URL
}

// AuthNotice is the inline message on the sign-in page: no account for the email, a success note, or an error.
type AuthNotice struct {
	SignupURL       string
	PersonalEmail   bool
	ExistingAccount bool
	Success         string
	Error           string
}

// NewAuthTabs builds the Sign in / Create account tab links for path, keeping every other query param.
func NewAuthTabs(enableSignup bool, path string, query url.Values) AuthTabs {
	signIn := url.Values{}
	signup := url.Values{}
	for k, v := range query {
		signIn[k] = v
		signup[k] = v
	}
	signIn.Del(ScreenHintParam)
	signup.Set(ScreenHintParam, ScreenHintSignup)
	return AuthTabs{
		SignupMode: enableSignup && query.Get(ScreenHintParam) == ScreenHintSignup,
		SignInURL:  template.URL(path + "?" + signIn.Encode()),
		SignupURL:  template.URL(path + "?" + signup.Encode()),
	}
}

// WithoutScreenHint drops the sign-up intent so links meant for signing in open on the Sign in tab.
func WithoutScreenHint(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	q := u.Query()
	if !q.Has(ScreenHintParam) {
		return link
	}
	q.Del(ScreenHintParam)
	u.RawQuery = q.Encode()
	return u.String()
}

// WithoutAccountCreated drops the one-shot sign-up hand-off so it does not leak into other links.
func WithoutAccountCreated(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = v
	}
	out.Del(AccountCreatedParam)
	out.Del(LoginHintParam)
	return out
}

// LoginO2 renders the connector chooser with the fork's sign-up tabs and hidden-connector flags.
func (t *Templates) LoginO2(r *http.Request, w http.ResponseWriter, connectors []ConnectorInfo, tabs AuthTabs, signupPath string, enableSignup bool) error {
	sortConnectors(connectors)
	data := struct {
		Connectors   []ConnectorInfo
		ReqPath      string
		Tabs         AuthTabs
		SignupMode   bool
		SignupPath   template.URL
		EnableSignup bool
	}{connectors, r.URL.Path, tabs, tabs.SignupMode, template.URL(signupPath), enableSignup}
	return renderTemplate(w, t.loginTmpl, data)
}

// PasswordO2 renders the fork's two-stage (email, then password) sign-in page.
func (t *Templates) PasswordO2(r *http.Request, w http.ResponseWriter, postURL, lastUsername, usernamePrompt string, lastWasInvalid bool, backLink string, signupPath string, resetPasswordPath string, enableSignup bool, initialStage bool, tabs AuthTabs, notice AuthNotice) error {
	if lastWasInvalid {
		w.WriteHeader(http.StatusUnauthorized)
	}
	data := struct {
		PostURL            string
		BackLink           string
		Username           string
		UsernamePrompt     string
		Invalid            bool
		ReqPath            string
		ShowRememberMe     bool
		RememberMeChecked  bool
		SignupPath         template.URL
		ResetPasswordPath  template.URL
		EnableSignup       bool
		InitialStage       bool
		Tabs               AuthTabs
		SignupMode         bool
		NoAccount          bool
		NoAccountSignupURL template.URL
		PersonalEmail      bool
		ExistingAccount    bool
		Success            string
		Error              string
	}{
		PostURL:            postURL,
		BackLink:           backLink,
		Username:           lastUsername,
		UsernamePrompt:     usernamePrompt,
		Invalid:            lastWasInvalid,
		ReqPath:            r.URL.Path,
		SignupPath:         template.URL(signupPath),
		ResetPasswordPath:  template.URL(resetPasswordPath),
		EnableSignup:       enableSignup,
		InitialStage:       initialStage,
		Tabs:               tabs,
		SignupMode:         tabs.SignupMode,
		NoAccount:          notice.SignupURL != "" || notice.PersonalEmail,
		NoAccountSignupURL: template.URL(notice.SignupURL),
		PersonalEmail:      notice.PersonalEmail,
		ExistingAccount:    notice.ExistingAccount,
		Success:            notice.Success,
		Error:              notice.Error,
	}
	return renderTemplate(w, t.passwordTmpl, data)
}

// Signup renders the sign-up page; a non-zero status marks a re-render after a failed submission.
func (t *Templates) Signup(r *http.Request, w http.ResponseWriter, postURL, lastEmail, lastUsername, csrf, errorMsg string, status int, backLink string) error {
	lastWasInvalid := status != 0
	if lastWasInvalid {
		w.WriteHeader(status)
	}
	// Re-renders split the joined username back so the first/last name inputs keep what was typed.
	firstName, lastName, _ := strings.Cut(lastUsername, " ")
	data := struct {
		PostURL    string
		BackLink   string
		SignInLink string
		Email      string
		Username   string
		FirstName  string
		LastName   string
		Csrf       string
		Invalid    bool
		Error      string
		ReqPath    string
	}{postURL, backLink, WithoutScreenHint(backLink), lastEmail, lastUsername, firstName, lastName, csrf, lastWasInvalid, errorMsg, r.URL.Path}
	return renderTemplate(w, t.signupTmpl, data)
}

// PasswordReset renders the forgot-password page; a non-zero status marks a re-render after a failed submission.
func (t *Templates) PasswordReset(r *http.Request, w http.ResponseWriter, postURL, lastEmail, errorMsg string, status int, backLink string) error {
	lastWasInvalid := status != 0
	if lastWasInvalid {
		w.WriteHeader(status)
	}
	data := struct {
		PostURL  string
		BackLink string
		Email    string
		Invalid  bool
		Error    string
		ReqPath  string
	}{postURL, backLink, lastEmail, lastWasInvalid, errorMsg, r.URL.Path}
	return renderTemplate(w, t.passwordResetTmpl, data)
}
