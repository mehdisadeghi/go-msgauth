package authres

import (
	"reflect"
	"testing"
)

var parseTests = []msgauthTest{
	{
		value:      "",
		identifier: "",
		results:    nil,
	},
	{
		value:      "example.com 1; none",
		identifier: "example.com",
		results:    nil,
	},
	{
		value: "example.com; \r\n" +
			" \t spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		value: "example.com;" +
			"dkim=pass reason=\"good signature\" header.i=@mail-router.example.net;",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Reason: "good signature", Identifier: "@mail-router.example.net"},
		},
	},
	{
		value: "example.com;" +
			"dkim=pass reason=\"good; signature\" header.i=@mail-router.example.net;",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Reason: "good; signature", Identifier: "@mail-router.example.net"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;" +
			" spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5 (comment inside comment)) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5; comment with semicolon) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		value: "example.com;" +
			" auth=pass (cram-md5 \\( comment with escaped char) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		value: "foo.example.net (foobar) 1 (baz);" +
			" dkim (Because I like it) / 1 (One yay) = (wait for it) fail" +
			" policy (A dot can go here) . (like that) expired" +
			" (this surprised me) = (as I wasn't expecting it) 1362471462",
		identifier: "foo.example.net",
		results: []Result{
			&DKIMResult{Value: ResultFail, Reason: "", Domain: "", Identifier: ""},
		},
	},
	{
		value: "mx.example.com;\r\n" +
			"       dkim=pass header.i=@example.org header.s=selector header.d=\"example.org\";\r\n" +
			"       spf=pass (example.com: domain of user@example.org designates 192.0.2.1 as permitted sender) smtp.mailfrom=\"user@example.org\"",
		identifier: "mx.example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Domain: "example.org", Identifier: "@example.org"},
			&SPFResult{Value: ResultPass, From: "user@example.org"},
		},
	},
	{
		value: "example.com;" +
			" spf=pass (voilà) smtp.mailfrom=voilà@example.org",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "voilà@example.org"},
		},
	},
	{
		value:      "example.com; dkim=none",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultNone},
		},
	},
	{
		value: "example.com;" +
			" dkim=none;" +
			" spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultNone},
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		value: "example.com;" +
			" spf=pass smtp.mailfrom=example.net;" +
			" dkim=none",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
			&DKIMResult{Value: ResultNone},
		},
	},
	{
		value: "mx.example.com;\r\n" +
			"    dkim=none;\r\n" +
			"    dmarc=fail reason=\"No valid SPF, No valid DKIM\" header.from=example.org (policy=quarantine);\r\n" +
			"    spf=none (mx.example.com: domain of user@mail.example.org has no SPF policy) smtp.mailfrom=user@mail.example.org",
		identifier: "mx.example.com",
		results: []Result{
			&DKIMResult{Value: ResultNone},
			&DMARCResult{Value: ResultFail, Reason: "No valid SPF, No valid DKIM", From: "example.org"},
			&SPFResult{Value: ResultNone, From: "user@mail.example.org"},
		},
	},
}

var mustFailParseTests = []msgauthTest{
	{
		value:      " ; ",
		identifier: "",
		results:    nil,
	},
	{
		value:      "example.com 2; none",
		identifier: "example.com",
		results:    nil,
	},
}

func TestParse(t *testing.T) {
	for _, test := range append(msgauthTests, parseTests...) {
		identifier, results, err := Parse(test.value)
		if err != nil {
			t.Errorf("Expected no error when parsing header, got: %v", err)
		} else if test.identifier != identifier {
			t.Errorf("Expected identifier to be %q, but got %q", test.identifier, identifier)
		} else if len(test.results) != len(results) {
			t.Errorf("Expected number of results to be %v, but got %v", len(test.results), len(results))
		} else {
			for i := 0; i < len(results); i++ {
				if !reflect.DeepEqual(test.results[i], results[i]) {
					t.Errorf("Expected result to be \n%v\n but got \n%v", test.results[i], results[i])
				}
			}
		}
	}
	for _, test := range mustFailParseTests {
		_, _, err := Parse(test.value)
		if err == nil {
			t.Errorf("Expected an error when parsing header, but got none.")
		}
	}
}
