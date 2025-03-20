"""Example data and patterns for testing the TEE server."""

TOY_EXAMPLE = """HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 60

{
    "message": "JSON here. You're welcome.",
    "value": 12345,
    "success": true
}
"""

toy_example_patterns = [
    {
        "pattern_type": "json",
        "path": "$.value",
        "data_type": "number",
        "should_extract": True,
        "origin": "toy",
    }
]

AMAZON_EXAMPLE = """HTTP/2 200 OK
Content-Type: application/json
Content-Length: 256
Server: Server
Date: Fri, 07 Mar 2025 12:34:56 GMT
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://amazon.com
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Set-Cookie: session-id=145-9876543-1234567; Path=/; Secure; HttpOnly; SameSite=Strict
Set-Cookie: session-token=xyz123abc456def789ghi000; Path=/; Secure; HttpOnly; SameSite=Strict

{
  "orderId": "112-3456789-0123456",
  "status": "Confirmed",
  "orderDate": "2025-03-07T12:34:56Z",
  "totalAmount": {
    "currency": "USD",
    "value": "129.99"
  },
  "shipping": {
    "method": "Standard Shipping",
    "estimatedDelivery": "2025-03-10T18:00:00Z",
    "address": {
      "recipient": "John Doe",
      "line1": "1234 Elm Street",
      "line2": "Apt 567",
      "city": "Seattle",
      "state": "WA",
      "postalCode": "98101",
      "country": "US"
    }
  }
}
"""

amazon_example_patterns = [
    # Extract total amount value only
    {
        "pattern_type": "json",
        "path": "$.totalAmount.value",
        "data_type": "number",
        "should_extract": True,  # This value will be stored in nilDB
        "origin": "amazon",
    },
    # Redact all totalAmount fields
    {
        "pattern_type": "json",
        "path": "$.totalAmount",
        "include_children": True,  # Override default False since we want to redact all fields
        "data_type": "string",
        "should_extract": False,
        "origin": "amazon",
    },
    # Redact shipping info (no extraction)
    {
        "pattern_type": "json",
        "path": "$.shipping",
        "include_children": True,  # Override default False since we want to redact all fields
        "data_type": "string",
        "should_extract": False,
        "origin": "amazon",
    },
    # Redact order details (no extraction)
    {
        "pattern_type": "json",
        "path": "$['orderId', 'orderDate']",
        "data_type": "string",
        "should_extract": False,
        "origin": "amazon",
    },
]

TIKTOK_EXAMPLE = """HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Tt-Logid: 20250319034817C8F82C062B76D85060AC
Tt_stable: 1
Strict-Transport-Security: max-age=31536000; includeSubDomains
Server-Timing: inner; dur=49
x-tt-trace-host: 0117c8a58db80687f017a47411e26bb1d3ff3a01d3d9f8e2203025de4b7973eae5119ef434c615da22a29033c1f11f5296a01f139607ca98ad4182bbd10d1e2aee696436591a0153d84d2e93f6b154be7afadd2a9fd8e0c1351bb8e42c8c2d2573
x-tt-trace-id: 00-250319034817C8F82C062B76D85060AC-59A3C7B5387B49BD-00
Server: TLB
Vary: Accept-Encoding
Expires: Wed, 19 Mar 2025 03:48:19 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Wed, 19 Mar 2025 03:48:19 GMT
Content-Length: 556
X-Cache: TCP_MISS from a23-40-40-36.deploy.akamaitechnologies.com (AkamaiGHost/22.0.0.1-318443691900e5d3d78f5dd48f596007) (-)
Connection: keep-alive
x-tt-trace-tag: id=16;cdn-cache=hit;type=dyn
Server-Timing: cdn-cache; desc=MISS, edge; dur=2, origin; dur=54
X-Origin-Response-Time: 54,23.40.40.36
X-Akamai-Request-ID: 1a54172

{"data":{"block_coin_page":false,"coins":0,"frozen_coins":0,"has_google_recharge":false,"is_allow":true,"is_email_confirmed":false,"is_first_web_recharge":true,"is_periodic_payout":false,"is_show":true,"quick_payment_available":true,"redeem_info":{"coins_balance":11,"frozen_coins_balance":0,"is_enabled":true,"is_first_recharge":true,"is_first_web_recharge":true,"is_region_enabled":false},"show_input_tooltip":true,"show_recharge_amount_adjusted_text":false,"verified_email":"","web_recharge_input_option":0},"extra":{"now":1742356099043},"status_code":0}
"""

tiktok_example_patterns = [
    # Extract and redact coins balance
    {
        "pattern_type": "json",
        "path": "$.data.redeem_info.coins_balance",
        "data_type": "number",
        "should_extract": True,  # This value will be stored in nilDB
        "origin": "tiktok",
    },
    # Redact all redeem info (no extraction)
    {
        "pattern_type": "json",
        "path": "$.data.redeem_info",
        "include_children": True,  # Override default False since we want to redact all fields
        "data_type": "string",
        "should_extract": False,  # Explicitly set to False for redaction
        "origin": "tiktok",
    },
]

# Dictionary mapping example names to their data and patterns
EXAMPLES = {
    "toy": (TOY_EXAMPLE, toy_example_patterns),
    "amazon": (AMAZON_EXAMPLE, amazon_example_patterns),
    "tiktok": (TIKTOK_EXAMPLE, tiktok_example_patterns),
}
