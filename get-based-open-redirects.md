## Title: GET-Based Open Redirect at [  ]

---

## Overview of the Vulnerability

Open redirects enable an attacker to manipulate a user by redirecting them to a malicious site. A GET-based open redirect was identified which can impact users' ability to trust legitimate web pages. An attacker can send a phishing email that contains a link with a legitimate business name in the URL and the user will be redirected from the legitimate web server to any external domain. Users are less likely to notice subsequent redirects to different domains when an authentic URL with a valid SSL certificate can be used within the phishing link.

This type of attack is also a precursor for more serious vulnerabilities such as Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), Cross-Site Request Forgery (CSRF), or successful phishing attempts where an attacker can harvest users' credentials or gain users' OAuth access by relaying them through an Open Redirection, to a server they control (and can see the inbound requests from).

## Business Impact

The identified GET-based open redirect vulnerability poses significant business risks. Customers' trust in the affected organization can be severely compromised, leading to reputational damage. Attackers can exploit the vulnerability to redirect users to phishing websites, where they are coerced into disclosing sensitive information like login credentials or engaging in fraudulent financial transactions.

## Steps to Reproduce

1. Using a browser, navigate to: []()
1. Copy and modify the URI so that the URL redirects to `evil.com`
1. Submit this in a new browser window and you should be redirected to the Bugcrowd website.

## Proof of Concept (PoC)



## Mitigation

- Simply avoid using redirects and forwards.
- If used, do not allow the URL as user input for the destination.
- Where possible, have the user provide short name, ID or token which is mapped server-side to a full target URL.
	- This provides the highest degree of protection against the attack tampering with the URL.
	- Be careful that this doesn't introduce an enumeration vulnerability where a user could cycle through IDs to find all possible redirect targets
- If user input can’t be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.
- Sanitize input by creating a list of trusted URLs (lists of hosts or a regex).
	- This should be based on an allow-list approach, rather than a block list.
- Force all redirects to first go through a page notifying users that they are going off of your site, with the destination clearly displayed, and have them click a link to confirm.

## Safe URL Redirects

When we want to redirect a user automatically to another page (without an action of the visitor such as clicking on a hyperlink) you might implement a code such as the following:

- Java

```java
response.sendRedirect("http://www.mysite.com");
```
- PHP

```php
<?php
/* Redirect browser */
header("Location: http://www.mysite.com");
/* Exit to prevent the rest of the code from executing */
exit;
?>
```
- ASP .NET

```aspx
Response.Redirect("~/folder/Login.aspx")
```

- Rails

```ruby
redirect_to login_path
```
- Rust actix web

```rust
  Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, "https://mysite.com/"))
        .finish())
```

In the examples above, the URL is being explicitly declared in the code and cannot be manipulated by an attacker.

## References

- [CWE Entry 601 on Open Redirects](http://cwe.mitre.org/data/definitions/601.html).
- [WASC Article on URL Redirector Abuse](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [Google blog article on the dangers of open redirects](https://googlewebmastercentral.blogspot.com/2009/01/open-redirect-urls-is-your-site-being.html).
- [Preventing Open Redirection Attacks (C#)](https://www.asp.net/mvc/tutorials/security/preventing-open-redirection-attacks).
