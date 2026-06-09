Title: Trusted Until It Isn't: The Zabbix SQL Injection That "Needs an Admin"
Date: 2026-06-08 11:00
Slug: zabbix-oauth-sql-injection
Author: Argus
Category: Security
Tags: zabbix, sqli, oauth, disclosure
Summary: Zabbix takes data from an external OAuth server's response and drops it straight into a SQL `UPDATE` statement with zero escaping. When we reported this, Zabbix dismissed it as a non-issue because "an admin has to configure the OAuth provider." That defense points at the wrong end of the data flow.


Zabbix is one of the most widely deployed open source monitoring platforms, used by everyone from small shops to large enterprises to keep an eye on servers, networks, and applications. A central Zabbix server collects metrics from across the fleet, evaluates alerting rules, and sends notifications when something goes wrong. Because it sits in the middle of all that infrastructure and holds the credentials to reach it, the Zabbix server is a high value target: whoever controls it has a foothold into much of the environment it watches.

We recently found a SQL injection in the Zabbix server's OAuth2 token refresh path. The injected values come directly from an external HTTP response, not from user input. Yet, when we reported the vulnerability, Zabbix declined to treat it as a security issue. Their rationale? An administrator has to configure the OAuth media type in the first place.

But the privilege to select an OAuth endpoint is not the same as the privilege to supply the bytes that get executed in your database. This post breaks down the bug, the data flow, and why "you need an admin" is an answer to a question nobody asked.

## The bug

When an Email media type is configured with OAuth2 authentication and the access token expires, Zabbix server POSTs to the configured token endpoint to refresh it. It then takes the `access_token` and `refresh_token` strings out of the JSON response and writes them into the database.

Here is the write, in `src/libs/zbxalerter/oauth.c`, lines 301 to 307:

```c
zbx_db_execute("update media_type_oauth set"
        " access_token='%s',access_token_updated=" ZBX_FS_TIME_T ","
        "access_expires_in=%d,refresh_token='%s',tokens_status=%hhu"
        " where mediatypeid="ZBX_FS_UI64,
        data->access_token, data->access_token_updated, data->access_expires_in,
        data->refresh_token, data->tokens_status,
        mediatypeid);
```

`data->access_token` and `data->refresh_token` are parsed straight out of the OAuth server's JSON response (`oauth.c:248-264`) and handed to `zbx_db_execute()` with no escaping at all. The `else` branch at lines 311 to 317 has the same problem for `access_token`.

The MySQL connection is opened with `CLIENT_MULTI_STATEMENTS`, so this is not limited to breaking the one UPDATE. An attacker who controls the response can append stacked queries: `INSERT`, `UPDATE`, `DELETE`, anything the database user can do.

The call chain is short and fully automatic:

1. `alert_manager.c:491`, the alerter processes an email alert that uses an OAuth2 media type
2. `oauth.c:400`, the token is detected as expired
3. `oauth.c:408`, `oauth_access_refresh()` POSTs to `token_url` from the database
4. `oauth.c:242-264`, the JSON response is parsed and `access_token` / `refresh_token` are taken as-is
5. `oauth.c:413`, `oauth_db_update()` is called with the unescaped values
6. `oauth.c:301-307`, the values are interpolated into SQL and executed

Nobody clicks anything. A trigger fires, an alert gets queued, the token happens to be expired (OAuth access tokens usually live minutes to hours), and the refresh runs on its own.

We belive this is a definitly bug, not a design choice, but you don't have to take our threat model on faith; Zabbix's own code disagrees with their triage. Look anywhere else in this codebase where data hits SQL, and you will find it passing through `zbx_db_dyn_escape_string()`. It is heavily utilized throughout `dbconn.c` for this exact reason.

## Why "an admin sets the OAuth URL" is the wrong objection

Zabbix's position is that configuring an Email media type (including setting the token endpoint) requires Admin rights. That is true, but it only gates the *destination*. It controls the URL Zabbix will talk to, not the data that comes back.

These are two entirely different trust boundaries, and the injection lives firmly on the second one:

* **Boundary 1 (Configuration):** The admin controls where Zabbix sends the refresh request. This is trusted and restricted to administrators.
* **Boundary 2 (Execution):** The injected SQL comes from the response body, the tokens returned by whatever is listening at that URL. That data crosses the network on every single refresh, and it is untrusted by definition.

The attacker exploiting this doesn't need to be the Zabbix admin.

## Why it is a critical issue

A successful injection grants arbitrary SQL execution as the Zabbix database user. With stacked queries enabled, an attacker can read every credential and secret in the database, alter monitoring data, manipulate alert states, trivially create a backdoor administrator by inserting a record directly into the `users` table, or possibly execute arbitrary code.

Our proof of concept spun up Zabbix 8.0.0beta2, MySQL, and a hostile OAuth server. We seeded an Email media type pointing at our server and let the alerter do its job. The hostile server returned an `access_token` carrying a stacked `INSERT` statement.

```
=== Users BEFORE injection ===
userid  username        passwd
1       Admin   $2y$10$92nDno4n0Zm7Ej7Jfsz8WukBfgSS/U0QkIuu8WkJPihXBb2A1UrEK
2       guest   $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06

[+] New admin appeared!

=== Users AFTER injection ===
userid  username        passwd
1       Admin   $2y$10$92nDno4n0Zm7Ej7Jfsz8WukBfgSS/U0QkIuu8WkJPihXBb2A1UrEK
2       guest   $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06
9999    backdoor        $2y$10$92nDno4n0Zm7Ej7Jfsz8WukBfgSS/U0QkIuu8WkJPihXBb2A1UrEK
```

Full database write on a monitoring server is about as high as impact gets, because a monitoring server already has reach into the rest of your fleet. Pair that with a reachability path that needs no Zabbix credentials at all (a provider compromise), and "not a security issue" is not a defensible call.

## The fix

Escape `access_token` and `refresh_token` with `zbx_db_dyn_escape_string()` before they are passed to `zbx_db_execute()` in `oauth_db_update()`, in both the `if` and `else` branches at lines 301 to 307 and 311 to 317. This is the same function the rest of the database layer already uses:

```c
diff --git a/src/libs/zbxalerter/oauth.c b/src/libs/zbxalerter/oauth.c
index dadca8f..b008c49 100644
--- a/src/libs/zbxalerter/oauth.c
+++ b/src/libs/zbxalerter/oauth.c
@@ -294,17 +294,29 @@ static void       oauth_db_update(zbx_uint64_t mediatypeid, zbx_oauth_data_t *data, in
        }
        else
        {
+               char    *access_token_esc;
+
                data->tokens_status |= (ZBX_OAUTH_TOKEN_ACCESS_VALID | ZBX_OAUTH_TOKEN_REFRESH_VALID);
 
+               /* access_token and refresh_token originate from the external OAuth server response, */
+               /* so they must be escaped before being interpolated into the SQL statement */
+               access_token_esc = zbx_db_dyn_escape_string(data->access_token);
+
                if (NULL != data->old_refresh_token)     /* data->refresh_token has changed */
                {
+                       char    *refresh_token_esc;
+
+                       refresh_token_esc = zbx_db_dyn_escape_string(data->refresh_token);
+
                        zbx_db_execute("update media_type_oauth set"
                                        " access_token='%s',access_token_updated=" ZBX_FS_TIME_T ","
                                        "access_expires_in=%d,refresh_token='%s',tokens_status=%hhu"
                                        " where mediatypeid="ZBX_FS_UI64,
-                                       data->access_token, data->access_token_updated, data->access_expires_in,
-                                       data->refresh_token, data->tokens_status,
+                                       access_token_esc, data->access_token_updated, data->access_expires_in,
+                                       refresh_token_esc, data->tokens_status,
                                        mediatypeid);
+
+                       zbx_free(refresh_token_esc);
                }
                else
                {
@@ -312,10 +324,12 @@ static void       oauth_db_update(zbx_uint64_t mediatypeid, zbx_oauth_data_t *data, in
                                        " access_token='%s',access_token_updated=" ZBX_FS_TIME_T ","
                                        "access_expires_in=%d,tokens_status=%hhu"
                                        " where mediatypeid="ZBX_FS_UI64,
-                                       data->access_token, data->access_token_updated, data->access_expires_in,
+                                       access_token_esc, data->access_token_updated, data->access_expires_in,
                                        data->tokens_status,
                                        mediatypeid);
                }
+
+               zbx_free(access_token_esc);
        }
 }
```

## Closing remarks

We reported this vulnerability in good faith, providing a fully functional proof of concept. Zabbix concluded it was not a security issue because setting up the OAuth provider requires an administrator.

We disagree. Their reasoning treats the privilege to *choose* an endpoint as the privilege to *control* that endpoint's responses.

*Affected version: Zabbix 8.0.0beta2, commit `31eccf9ddaf7adf129f9cd611c85b7451b188eb9`.*
