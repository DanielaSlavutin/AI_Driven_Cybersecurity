# Lab 4: Adversarial WAF Rule Testing Workflow

## Workflow Purpose
This workflow addresses the challenge of writing robust Web Application Firewall (WAF) rules. It simulates an adversarial environment where a user-defined WAF rule is immediately stress-tested against dynamically generated attack payloads, helping administrators identify blind spots, bypass techniques or false positives.

## Agents Description:
1. **RedTeamAgent:** An offensive agent. Its sole responsibility is to take simple WAF rule and generate 3 distinct HTTP payloads designed to bypass or test the rule (District Bypass, Different Vector and False Positive).
2. **BlueTeamAgent:** A defensive evaluator agent. It takes both the user's original rule and the Red Team's payloads, analyzes whether the rule would successfully block the attacks and provides actionable recommendations to improve the rule.

## Workflow Logic
1. The user inputs a WAF rule in plain English via Chainlit UI.
2. The input is routed to the `RedTeamAgent` agent, which generates 3 test payloads.
3. The generated payloads are displayed to the user as an intermediate step.
4. Both the original WAF rule and the generated payloads are combined into a new prompt and routed to the `BlueTeamAgent` agent.
5. The `BlueTeamAgent` outputs the final evaluation and recommendations.

## Security Rationale
In real-world SOC and AppSec environments, defensive rules often fail due to unexpected encodings, fragmentation or overly broad definitions (causing FPs). This adversarial workflow reduces risk by automatically exposing a rule to an attackeer's mindset *before* deployment, ensuring the final policy is resilient and precise.

## Conversation Example:
* **User:** Drop requests where the URL contains '../', '..' or any other way or manipulation to trying access site's files

* **Red Team Agent:** 
Red Team is generating attack payloads...
Bypass Attempts
**Direct Bypass**: `GET /.%2e/%2e/../../etc/passwd HTTP/1.1`
**Different Vector**: `GET /index.php?file=../../../../etc/passwd HTTP/1.1`
**False Positive**: `GET /products/../category/electronics HTTP/1.1`

* **Blue Team Agent:**
Analyzing the provided WAF rule against the Red Team payloads:

1. **Direct Bypass**: `GET /.%2e/%2e/../../etc/passwd HTTP/1.1`
   - The WAF rule would **FAIL TO BLOCK** this payload because it does not directly contain '../' or '..' in its URL path due to URL encoding (%2e represents '.'), which might not be decoded by the WAF before applying the rule.

2. **Different Vector**: `GET /index.php?file=../../../../etc/passwd HTTP/1.1`
   - The WAF rule would **FAIL TO BLOCK** this payload because it only checks the URL path and not query parameters. The payload uses a query parameter to attempt directory traversal, which is not covered by the current WAF rule.

3. **False Positive**: `GET /products/../category/electronics HTTP/1.1`
   - The WAF rule would **SUCCESSFULLY BLOCK** this payload because it contains '../' in the URL path. However, this might be a legitimate request and could result in a false positive, potentially blocking valid traffic.

Recommendation:
To improve the WAF rule, consider the following adjustments:
- Enhance the rule to decode URLs before applying checks to prevent bypasses like the **Direct Bypass**.
- Extend the rule to inspect query parameters for directory traversal attempts, like in the **Different Vector** payload.
- Refine the rule to differentiate between malicious directory traversal attempts and legitimate uses of '../' to minimize false positives, such as the **False Positive** scenario. Implementing a more sophisticated detection mechanism, such as analyzing the request's intent and context, could help in making the rule more effective and less prone to false positives.
