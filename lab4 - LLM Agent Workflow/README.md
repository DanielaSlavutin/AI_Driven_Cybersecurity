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