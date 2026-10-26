### The triage method (use it for every alert)

Alert triage means investigating an alert and deciding, with evidence, whether it is a **real attack (True Positive)** or a **false alarm (False Positive)**, then closing it with a written reason or escalating it.

**1. Pick by severity, not by time.** Work Critical first, then High, Medium, Low. A ten-minute-old Critical beats a two-minute-old Low.

**2. Take ownership.** Assign the alert to yourself and set it to *In Progress*, so nobody works it twice.

**3. Answer the 5 Ws (and How) from the evidence.**

| | Ask | Typical evidence |
|---|---|---|
| **Who** | Which user, account and source IP? Internal or external? Privileged (root, Administrator, SYSTEM)? | user field, source IP, account type |
| **What** | What exactly happened? Which commands, files, how many events? | rule description, raw events, command line, file name |
| **When** | What time, for how long? Working hours? What happened just before and after? | timestamps, other alerts from the same IP or host |
| **Where** | Which host or server, and how important is it (DMZ, domain controller, laptop)? | host name, network zone, asset owner |
| **Why** | Is there a legitimate reason? Change ticket, the user's role, a known IT script or scanner? | ticketing system, asking the user or their manager |
| **How** | Which technique? What process chain or protocol? | MITRE technique, parent and child processes, ports |

The tool fills in what it can read from the alert. **Why** is almost always yours to answer: it needs context the logs do not have.

**4. Weigh the signs.** Each playbook lists signs that point to True Positive and signs that point to False Positive. One strong sign (a successful login after many failures, a cleared audit log, a shell banner) can be enough; weak signs need to add up.

**5. Decide.**
- **True Positive:** real and malicious. Contain if the playbook allows, and escalate with your evidence.
- **Benign True Positive:** the rule was right, but the activity was authorised (a pentest, an approved admin task). Close with the reason.
- **False Positive:** the rule fired on harmless activity. Close with the reason, and note it so the rule can be tuned.
- **Unsure?** Escalate with what you checked. Escalating with notes is never wrong; silently closing a real attack is.

**6. Write the comment, then close.** Facts first (who, what, when, where), then your reasoning (why), the verdict, and the next step. Someone else must be able to understand your decision without asking you.
