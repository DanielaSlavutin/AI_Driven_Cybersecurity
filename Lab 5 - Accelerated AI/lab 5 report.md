# Lab 5 - Event-Driven Cybersecurity Pipeline with Kafka and Tracing - Observation Report

---

## Why is Kafka used instead of direct function calls?
Kafka enables asynchronous processing and decoupling. If there is a direct call to a function and it crashes or is busy, the entire program might crash or slow down and critical information could be lost. Because Kafka decouples the components, it acts as a reliable buffer. The producer simply sends the event data to the queue and continues its operation without having to wait for the consumer to be ready.

## What happens if the consumer is slower than the producer?
If the consumer is slower than the producer, the event logs simply accumulate within Kafka's queue. No data is lost, but this will cause increased latency in processing times until the consumer manages to process the backlog and empty the queue.

## How does tracing help debug pipeline behavior?
Tracing provides full visibility into the pipeline's execution. By following the trace of an event, it is much easier to detect errors, measure latency per stage, and identify performance bottlenecks within the architecture.

## Which pipeline stages could be scaled independently?
Because Kafka makes the architecture independent and asynchronous, **all stages** can be scaled independently.

## How would this pipeline change in a real SOC system?
1. **Producers:** These would be actual network sensors such as Firewalls, Switches, Routers and EDR/XDR agents streaming live telemetry and logs.
2. **Consumers:** The processing engines would cross-reference the incoming data with CTI feeds and utilize smart anomaly detection and correlation engines.
3. **Storage and Escalation:** The data would flow into enterprise SIEM/SOAR platforms. If a critical MITRE ATT&CK tactic alert occurs, the system would automatically create an incident ticket for SOC Analysts to investigate, or trigger a SOAR playbook to execute an immediate block of the malicious IP or domain.