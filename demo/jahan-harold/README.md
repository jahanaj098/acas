# Jahan and Harold — offline ACAS demo

All credentials are fake. Responses are simulated, not obtained from a server. Requests are transformed by the production ReplayEngine/CredentialPolicy and exported by HermesExport. This is not a live Burp UI test.

Two private resources, two owner captures, six probe records. Both swaps are denied in this simulated scenario.

## Owner: jahan

### baseline

```http
GET /api/v1/users/jahan/private-profile HTTP/2
Accept: application/json
Authorization: Bearer demo_jahan_access
Cookie: session_id=demo_jahan_sid; access_token=demo_jahan_access; refresh_token=demo_jahan_refresh; csrf_token=demo_jahan_csrf; XSRF-TOKEN=demo_jahan_xsrf; user_id=jahan; tenant_id=demo_jahan_tenant; device_id=demo_jahan_device; _ga=demo_analytics; preferences=lang%3Den; login_state=authenticated; mfa_verified=true
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-Access-Token: demo_jahan_extra_token
X-API-Key: demo_jahan_api
X-App-Version: 2.4.1
X-Auth-Token: demo_jahan_auth
X-Client-ID: demo_jahan_client
X-CSRF-Token: demo_jahan_csrf
X-Device-ID: demo_jahan_device
X-Request-ID: req_jahan_001
X-Session-ID: demo_jahan_session
X-Tenant-ID: demo_jahan_tenant
X-XSRF-TOKEN: demo_jahan_xsrf


HTTP/2 200 OK
Content-Type: application/json

{"userId":"jahan","email":"jahan@example.test","privateNote":"jahan private profile"}
```

### swap-as-harold

```http
GET /api/v1/users/jahan/private-profile HTTP/2
Accept: application/json
Authorization: Bearer demo_harold_access
Cookie: session_id=demo_harold_sid; access_token=demo_harold_access; refresh_token=demo_harold_refresh; csrf_token=demo_harold_csrf; XSRF-TOKEN=demo_harold_xsrf; user_id=harold; tenant_id=demo_harold_tenant; device_id=demo_harold_device; _ga=demo_analytics; preferences=lang%3Den; login_state=authenticated; mfa_verified=true
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-API-Key: demo_harold_api
X-App-Version: 2.4.1
X-Auth-Token: demo_harold_auth
X-Client-ID: demo_harold_client
X-CSRF-Token: demo_harold_csrf
X-Device-ID: demo_harold_device
X-Request-ID: req_jahan_001
X-Session-ID: demo_harold_session
X-Tenant-ID: demo_harold_tenant
X-XSRF-TOKEN: demo_harold_xsrf


HTTP/2 403 Forbidden
Content-Type: application/json

{"error":"forbidden","message":"You cannot read another account's private profile"}
```

### anonymous

```http
GET /api/v1/users/jahan/private-profile HTTP/2
Accept: application/json
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-App-Version: 2.4.1
X-Request-ID: req_jahan_001


HTTP/2 401 Unauthorized
Content-Type: application/json

{"error":"authentication_required"}
```

## Owner: harold

### baseline

```http
GET /api/v1/users/harold/private-profile HTTP/2
Accept: application/json
Authorization: Bearer demo_harold_access
Cookie: session_id=demo_harold_sid; access_token=demo_harold_access; refresh_token=demo_harold_refresh; csrf_token=demo_harold_csrf; XSRF-TOKEN=demo_harold_xsrf; user_id=harold; tenant_id=demo_harold_tenant; device_id=demo_harold_device; _ga=demo_analytics; preferences=lang%3Den; login_state=authenticated; mfa_verified=true
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-API-Key: demo_harold_api
X-App-Version: 2.4.1
X-Auth-Token: demo_harold_auth
X-Client-ID: demo_harold_client
X-CSRF-Token: demo_harold_csrf
X-Device-ID: demo_harold_device
X-Request-ID: req_harold_001
X-Session-ID: demo_harold_session
X-Tenant-ID: demo_harold_tenant
X-XSRF-TOKEN: demo_harold_xsrf


HTTP/2 200 OK
Content-Type: application/json

{"userId":"harold","email":"harold@example.test","privateNote":"harold private profile"}
```

### swap-as-jahan

```http
GET /api/v1/users/harold/private-profile HTTP/2
Accept: application/json
Authorization: Bearer demo_jahan_access
Cookie: session_id=demo_jahan_sid; access_token=demo_jahan_access; refresh_token=demo_jahan_refresh; csrf_token=demo_jahan_csrf; XSRF-TOKEN=demo_jahan_xsrf; user_id=jahan; tenant_id=demo_jahan_tenant; device_id=demo_jahan_device; _ga=demo_analytics; preferences=lang%3Den; login_state=authenticated; mfa_verified=true
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-Access-Token: demo_jahan_extra_token
X-API-Key: demo_jahan_api
X-App-Version: 2.4.1
X-Auth-Token: demo_jahan_auth
X-Client-ID: demo_jahan_client
X-CSRF-Token: demo_jahan_csrf
X-Device-ID: demo_jahan_device
X-Request-ID: req_harold_001
X-Session-ID: demo_jahan_session
X-Tenant-ID: demo_jahan_tenant
X-XSRF-TOKEN: demo_jahan_xsrf


HTTP/2 403 Forbidden
Content-Type: application/json

{"error":"forbidden","message":"You cannot read another account's private profile"}
```

### anonymous

```http
GET /api/v1/users/harold/private-profile HTTP/2
Accept: application/json
Host: app.example.test
Referer: https://app.example.test/dashboard
User-Agent: ACAS-Offline-Demo/1.0
X-App-Version: 2.4.1
X-Request-ID: req_harold_001


HTTP/2 401 Unauthorized
Content-Type: application/json

{"error":"authentication_required"}
```
