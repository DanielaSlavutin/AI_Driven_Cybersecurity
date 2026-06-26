# Lab 3 - AG2 LLM Agent - Password Evaluation Agent

## 1. Agent Name

**Password_Checker**

---

## 2. Agent Purpose

The purpose of the agent is to act as a strict cybersecurity assistant that evaluates the strength of user passwords.

It is designed to enforce complex password policies by checking for length, character variey (uppercase, lowercare, digits, special characters) and actively preventing predoctable dictionary/brute force patterns (such as sequential numbers or capitalized words followed by numbers).

---

## 3. Agent Tools

**`password_checker(password: str)`**
* **What iy does:** Evaluates the password against length requirements, character complexity, and blocks predictable dictionary patterns using Regular Expressions.
* **Expected input:** A signle string representing the exact raw password provided by the user.
* **Returned output:** A string message categorizing the password as "Weak", "Medium" or "Strong", along with an explanation of why it received that evaluation.

---
### 4. Conversation Example:
* **User Suggesting a Weak Password:**
  <img width="581" height="257" alt="צילום מסך 2026-06-26 151323" src="https://github.com/user-attachments/assets/f6a50a07-51dc-4e9b-88ae-a77a39f29f9a" />

* **User Suggesting a String Password:**
  <img width="581" height="262" alt="צילום מסך 2026-06-26 151408" src="https://github.com/user-attachments/assets/bba9fd6a-ec8a-4084-b94d-36025339629b" />


