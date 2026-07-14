# SafeWeb-AI

## Autonomous AI-Powered Multi-Agent Web Application Vulnerability Scanner and Offensive Penetration Testing Platform

**University:** Mansoura University  
**Faculty:** Faculty of Computer and Information Sciences  
**Department:** Information Systems  
**Academic Year:** 2025–2026

### Project Team
• Kareem Reda Ahmed AbdelRahman- System Analyst
• Magdy Nabil Mohammed Mohammed - UI/UX Designer
• Tarek El Said Mohammed El Said - UI/UX Designer
• Ahmed Abbas Ahmed Mohammed - Frontend Developer
• Mohammed El Sayed Mohammed Al Morsy - Frontend Developer
• Ahmed Gomaa AbdelKader El Said - Backend Developer
• Omar Reda El Sayed Ammar - AppSec Engineer
• Mohammed Tayseer Monir Tayseer - AppSec Engineer
• Mohammed Mostafa Ahmed Mohammed - AI/ML Engineer
• Mohammed Ahmed Mohammed El Saeed - Cloud/DevOps Engineer
### Academic Supervision
• Dr. Shahenda El Kholy - Supervisor
• Eng. Ahmed Emad El Deen - Co-Supervisor

# Abstract
Modern web applications are high-value targets for adversaries because they continuously
expose dynamic interfaces, API endpoints, authentication flows, third-party dependencies,
and cloud-integrated infrastructure. Traditional security assessment approaches remain
limited by manual effort, fragmented tooling, high false-positive rates, and insufficient
operational scalability for continuous assessment. This thesis presents SafeWeb-AI, an AI-
assisted web application vulnerability scanner designed as a production-oriented
cybersecurity platform that combines automated reconnaissance, deep crawling, analyzer
pipelines, vulnerability testing, evidence verification, and risk-oriented reporting.
SafeWeb-AI adopts a layered architecture that integrates a React frontend, a Django REST
backend, Celery-based asynchronous workers, Redis queueing, PostgreSQL persistence,
object storage, and an AI assistant layer for contextual remediation guidance. The scanning
subsystem executes a multi-phase pipeline that includes target validation, reconnaissance,
attack-surface expansion, crawler-driven endpoint discovery, category-based vulnerability
testing, cross-finding correlation, confidence adjustment, and security score computation.
The platform further supports real-time scan progress streaming, report export,
administrative governance features, and chatbot-based assistance grounded in scan
context.
From an engineering perspective, this work contributes a unified architecture for
orchestrating heterogeneous security tools and in-house testing logic under one auditable
workflow. From an academic perspective, it formalizes a system analysis and design
approach that connects requirements engineering, software architecture, data modeling,
implementation strategy, and evaluation criteria in a single cybersecurity artifact. The
resulting system demonstrates how AI can be embedded as an assistive layer in
vulnerability management without replacing deterministic security controls.
The thesis documents SafeWeb-AI from first principles through implementation and
evaluation, with emphasis on architectural rationale, subsystem interactions, operational
constraints, and extensibility. It provides a detailed reference for future researchers and
engineering teams seeking to build scalable AI-assisted defensive security platforms.

# Acknowledgements
We would like to express our sincere gratitude to our supervisor, Dr. Shahenda El Kholy,
for her academic guidance, technical feedback, and continuous support throughout the
lifecycle of this graduation project. Her direction significantly strengthened both the
research quality and the engineering discipline of this work.
We also extend our thanks to our co-supervisor, Eng. Ahmed Emad El Deen, for his
practical mentorship, constructive review sessions, and consistent encouragement during
analysis, design, and implementation stages.
We gratefully acknowledge our faculty and department for providing the academic
environment, resources, and evaluation framework that enabled this project to mature into
a complete cybersecurity platform rather than a limited prototype.
We also thank the maintainers of open-source cybersecurity and software tooling
ecosystems, including communities behind vulnerability research resources, testing
frameworks, and development platforms that informed our methodology and
implementation decisions.
Finally, we thank our families and colleagues for their patience, trust, and support during
the intensive effort required to complete this thesis and the SafeWeb-AI system.

# Table of Contents
• Front Matter
• Title Page
• Abstract
• Acknowledgements
• Table of Contents
• List of Figures
• List of Tables
• List of Abbreviations
• Chapter 1
• Chapter 2
• Chapter 3
• Chapter 4
• Chapter 5
• Chapter 6
• Chapter 7
• Chapter 8
• Chapter 9
• Chapter 10
• Chapter 11
• Chapter 12
• Chapter 13
• References
• Appendices

# List of Figures
Figure 3.1 System Context Diagram (DFD Level 0)
Figure 3.2 Authentication Sequence Diagram
Figure 3.3 Scan Lifecycle Sequence Diagram
Figure 3.4 AI Chatbot Sequence Diagram
Figure 3.5 Admin Operations Sequence Diagram
Figure 3.6 Scan Pipeline Activity Diagram
Figure 4.1 High-Level System Architecture
Figure 4.2 System Architecture Components
Figure 4.3 Internal Scanner Architecture
Figure 4.4 Cloud Deployment Architecture
Figure 4.5 Class Diagram
Figure 4.6 Database ERD
Figure 5.1 User Journey: Registration to First Scan
Figure 5.2 User Journey: Scan Review and Export
Figure 5.3 Dashboard Screen
Figure 5.4 Scan Configuration Screen
Figure 5.5 Live Scan Progress Screen
Figure 5.6 Scan Results Screen
Figure 5.7 Vulnerability Detail View
Figure 5.8 AI Chat Interface
Figure 5.9 Admin Dashboard Interface
Figure 6.1 Frontend Module Structure
Figure 7.1 Backend App Interaction Model
Figure 8.1 Scan Pipeline Phase Model
Figure 8.2 Tester Framework Inheritance Concept
Figure 8.3 Evidence Verification Flow
Figure 9.1 LLM-Assisted Action Flow

Figure 10.1 Production Cloud Service Topology
Figure 11.1 Test Strategy Coverage Matrix (visual map)
Figure H.1-H.47 Appendix H Figure Plates for Print
# List of Tables
Table 1.1 Summary of Project Objectives
Table 1.2 Summary of Contributions
Table 2.1 OWASP Top 10 Framing for SafeWeb-AI
Table 2.2 Security Tool Landscape and Functional Roles
Table 2.3 Comparison Matrix: Manual vs Conventional vs AI-Assisted Scanning
Table 3.1 Stakeholder Responsibilities
Table 3.2 Functional Requirements Catalogue
Table 3.3 Non-Functional Requirements and Acceptance Targets
Table 3.4 Core Use Cases
Table 3.5 Operational Risks and Constraints
Table 4.1 Architecture Layers and Responsibilities
Table 4.2 Component Responsibilities and Interfaces
Table 4.3 Data Entities and Business Role Mapping
Table 4.4 Security Boundary and Control Mapping
Table 5.1 UI/UX Design Principles and Interface Implications
Table 5.2 Key User Journeys and Success Criteria
Table 6.1 Frontend Folder and Module Responsibility Map
Table 6.2 Frontend Error Handling Strategy
Table 7.1 API Domain Grouping and Purpose
Table 7.2 Authentication and Authorization Decision Matrix
Table 8.1 Scan Phases and Primary Outputs
Table 8.2 Vulnerability Tester Categories
Table 8.3 External Tool Integration Categories

Table 8.4 Risk Score Deduction Rules
Table 9.1 AI Assistant Capabilities and Boundaries
Table 9.2 ML Components and Feature Sets
Table 10.1 Cloud Services and Roles
Table 10.2 DevOps Pipeline Stage Mapping
Table 11.1 Testing Layers and Coverage Targets
Table 11.2 Reliability Scenarios and Expected System Behavior
Table 12.1 Results Discussion Framework
Table 13.1 Future Work Roadmap Prioritization
Table F.1 Business Model Canvas Summary
Table G.1 Requirement Traceability Matrix
# List of Abbreviations
• AI: Artificial Intelligence
• API: Application Programming Interface
• ASN: Autonomous System Number
• BDD: Behavior-Driven Development
• BFS: Breadth-First Search
• CI/CD: Continuous Integration / Continuous Delivery
• CLI: Command-Line Interface
• CMS: Content Management System
• CORS: Cross-Origin Resource Sharing
• CSP: Content Security Policy
• CSRF: Cross-Site Request Forgery
• CSS: Cascading Style Sheets
• CT: Certificate Transparency
• CWE: Common Weakness Enumeration
• CVE: Common Vulnerabilities and Exposures
• CVSS: Common Vulnerability Scoring System
• DAST: Dynamic Application Security Testing
• DBMS: Database Management System
• DFD: Data Flow Diagram
• DNS: Domain Name System
• DRF: Django REST Framework
• ERD: Entity-Relationship Diagram

• HTML: HyperText Markup Language
• HTTP: HyperText Transfer Protocol
• HTTPS: HyperText Transfer Protocol Secure
• IaC: Infrastructure as Code
• IDOR: Insecure Direct Object Reference
• IDS: Intrusion Detection System
• JWT: JSON Web Token
• LLM: Large Language Model
• ML: Machine Learning
• ORM: Object-Relational Mapping
• OSINT: Open-Source Intelligence
• OWASP: Open Worldwide Application Security Project
• PDF: Portable Document Format
• PoC: Proof of Concept
• RBAC: Role-Based Access Control
• RCE: Remote Code Execution
• REST: Representational State Transfer
• SaaS: Software as a Service
• SAST: Static Application Security Testing
• SQL: Structured Query Language
• SQLi: SQL Injection
• SSE: Server-Sent Events
• SSRF: Server-Side Request Forgery
• SSTI: Server-Side Template Injection
• TLS: Transport Layer Security
• TOTP: Time-Based One-Time Password
• UI: User Interface
• UML: Unified Modeling Language
• URL: Uniform Resource Locator
• UX: User Experience
• WAF: Web Application Firewall
• WHOIS: Domain Registration Information Protocol
• WSTG: Web Security Testing Guide
• XSS: Cross-Site Scripting

# Chapter 1: Introduction
This chapter is grounded in established web security risk framing and software
engineering design literature, including OWASP guidance, systems analysis references, and
the SafeWeb-AI technical corpus [1], [2], [7], [10], [49], [60], [61].
## 1.1 Background
Web applications have evolved from static service portals to highly dynamic, distributed
software ecosystems that expose rich functionality through browser interfaces, REST APIs,
asynchronous messaging, and external service integrations. This transformation has
increased business value and user convenience, but it has also substantially expanded the
attack surface. A modern web application no longer consists only of server-rendered pages.
It often includes client-side execution logic, JavaScript-heavy state transitions, token-based
authentication workflows, third-party scripts, cloud storage dependencies, and
continuously changing deployment pipelines. Each of these layers can introduce
exploitable security weaknesses when security assurance practices are fragmented or
delayed.
The cybersecurity landscape has consistently shown that web applications remain one of
the most frequently targeted vectors for unauthorized access, data theft, account takeover,
and service disruption. Attack classes such as SQL injection, cross-site scripting, server-side
request forgery, authentication bypass, insecure direct object reference, and
misconfiguration-based data exposure continue to appear because secure development
controls are unevenly adopted, and because post-deployment validation is often
incomplete. Even organizations with mature security teams face operational limits when
attempting to validate large sets of endpoints and parameter combinations using only
manual methods.
Automated scanning has therefore become a foundational requirement for defensive web
security operations. However, automation alone is insufficient when it is narrowly rule-
based or disconnected from context. Security teams must interpret scanner outputs, triage
low-confidence findings, connect seemingly isolated vulnerabilities into realistic attack
paths, and prioritize remediation under constrained resources. In practice, this creates a
gap between raw detection output and actionable security decisions.
SafeWeb-AI is designed against this backdrop. The system is an AI-assisted web application
vulnerability scanner that combines deterministic security testing, multi-stage
reconnaissance, structured vulnerability verification, and contextual AI-based assistance.
Its architecture integrates a React frontend, Django REST backend, Celery worker
execution, Redis queueing, PostgreSQL persistence, and object storage. The objective is not
merely to produce finding lists, but to construct a defensible workflow that supports
discovery, validation, prioritization, and remediation guidance.

## 1.2 Problem Statement
Despite extensive tooling availability, practical web security assessment still faces
structural weaknesses in both methodology and execution. The first weakness is
dependence on manual penetration testing for coverage-critical tasks. Manual testing offers
depth and expert judgment, but it does not scale efficiently for repeated assessments,
broad endpoint inventories, or continuously evolving applications. As development velocity
increases, manual-only workflows become periodic snapshots rather than continuous
assurance mechanisms.
The second weakness is fragmentation across single-purpose tools. Security practitioners
typically combine multiple utilities for reconnaissance, endpoint discovery, vulnerability
probing, and report generation. While this modularity is useful, tool chaining is frequently
ad hoc, leading to inconsistent data formats, weak orchestration, and duplicated effort.
Findings may be generated without robust correlation across phases, reducing confidence
in prioritization decisions.
The third weakness is high false-positive friction. Rule-based scanners are sensitive to
payload signatures and response heuristics, but they are not always effective in
distinguishing exploitable conditions from benign response artifacts. Excessive false
positives overload analysts, increase triage time, and can reduce trust in automated
systems.
The fourth weakness is limited operational scalability in conventional setups. Large
assessments require asynchronous execution, queue management, progress tracking, and
resilient failure handling. Many scanner workflows remain script-centric and are difficult to
govern through role-based interfaces, structured APIs, and auditable process controls.
The fifth weakness is the lack of integrated explanatory support. Security findings are often
technically dense and remediation pathways are not always obvious to mixed-experience
teams. An assistive intelligence layer can improve usability by providing contextual
explanation and remediation-oriented guidance, but this layer must remain bounded by
explicit safety and scope controls.
These limitations define the central problem addressed by this thesis: how to design and
implement a production-oriented, AI-assisted web vulnerability scanning platform that
combines broad automated coverage with actionable outputs, architectural scalability, and
defensible engineering practices.
## 1.3 Motivation
The motivation for SafeWeb-AI is both practical and academic.
From a practical perspective, organizations require repeatable, scalable, and interpretable
web security assessments. Existing workflows often force teams to choose between
breadth and depth: broad automated scans with noisy outputs, or high-confidence manual
assessments with limited frequency. SafeWeb-AI aims to reduce this trade-off by

orchestrating a multi-phase scan pipeline, incorporating evidence verification and risk
scoring, and presenting results through role-oriented interfaces.
From an academic perspective, the project provides an opportunity to unify disciplines that
are often treated independently in student projects: system analysis and design, secure
backend engineering, distributed task execution, frontend information architecture, AI-
assisted interaction design, and cloud deployment strategy. A graduation thesis in
cybersecurity should not end at vulnerability enumeration; it should demonstrate end-to-
end systems thinking, including requirements engineering, architecture rationale,
implementation traceability, and evaluation methodology.
The project is additionally motivated by the pedagogical value of documenting a complete
engineering artifact. By formalizing design decisions and implementation boundaries, the
thesis supports reproducibility, technical review, and future extension by new teams.
## 1.4 Objectives
The primary objective of SafeWeb-AI is to develop a robust platform for web application
vulnerability scanning that bridges deterministic security testing and contextual AI-
assisted analysis under a unified, scalable architecture.
### 1.4.1 General Objective
Design, implement, and document a production-oriented AI-assisted web application
vulnerability scanner that supports end-to-end security assessment workflows from target
submission through report generation and remediation support.
### 1.4.2 Specific Objectives
1. Implement a structured scanning pipeline that includes target validation,
reconnaissance, crawling, analyzer stages, vulnerability testing, verification,
correlation, risk scoring, and reporting.
2. Integrate heterogeneous external security tools within a normalized orchestration
model that tolerates tool availability variance and execution failures.
3. Provide asynchronous scan execution using worker-queue architecture to support
scalability and non-blocking user workflows.
4. Deliver real-time progress visibility and scan lifecycle transparency to end users
through streaming update mechanisms.
5. Implement a persistence model that captures scan state, vulnerabilities, evidence,
and reporting artifacts for auditability and historical comparison.
6. Provide an AI assistant layer that supports scan-aware explanation, workflow
actions, and remediation guidance while enforcing safe usage boundaries.
7. Establish role-aware interfaces and API boundaries for user operations,
administrative operations, and system governance.
8. Produce a formal thesis-grade system analysis and design artifact that includes
diagrams, requirements, architecture rationale, and implementation evidence.

### 1.4.3 Objective Summary
Objective ID Objective Statement Expected Outcome
OBJ-01 Build full scan lifecycle
pipeline
Structured, repeatable
assessment flow
OBJ-02 Integrate external security
tools
Broader detection coverage
across classes
OBJ-03 Introduce async
orchestration
Scalable execution and
better responsiveness
OBJ-04 Provide live scan
observability
Improved user trust and
operational transparency
OBJ-05 Persist findings and
evidence
Auditable security record
OBJ-06 Add AI assistive layer Better interpretation and
remediation guidance
OBJ-07 Enforce role and API
boundaries
Stronger governance and
safer operation
OBJ-08 Deliver formal technical
thesis
Academic and engineering
reproducibility
## 1.5 Contributions
This thesis contributes at multiple levels: architecture, security workflow design,
implementation strategy, and documentation rigor.
### 1.5.1 Engineering Contributions
1. A layered platform architecture combining frontend interface, API layer,
asynchronous processing, scanning engine subsystems, AI services, and persistent
storage.
2. A multi-phase scanning methodology that merges reconnaissance and active testing
into a coherent orchestration model.
3. A vulnerability processing workflow that extends beyond detection toward
verification, correlation, and risk-oriented prioritization.
4. Integration of AI assistance as a bounded support component rather than a
replacement for deterministic security logic.
5. Real-time scan state communication and report export pathways suitable for
operational usage.
### 1.5.2 Academic Contributions
1. A complete system analysis and design narrative tailored to a cybersecurity
platform, including requirements, use cases, architectural decomposition, and data
design.
2. A thesis structure that preserves traceability from problem statement through
implementation and evaluation.

3. A practical reference model for future student teams building distributed security
software with explainable outputs.
### 1.5.3 Contribution Summary
Contribution Type Contribution Value
Architectural Layered distributed scanner
platform
Supports extensibility and
maintenance
Methodological Multi-phase scan
orchestration
Improves systematic
coverage
Operational Async processing with live
updates
Improves usability and
scalability
Analytical Verification and scoring
integration
Improves finding confidence
Assistive Context-aware AI guidance Improves interpretation
efficiency
Academic End-to-end thesis
documentation
Supports reproducibility and
defense readiness
## 1.6 Scope and Limitations
A rigorous thesis must define not only what is implemented, but also what remains outside
the effective boundary of the current system version.
### 1.6.1 Project Scope
SafeWeb-AI covers the following core scope:
1. Web application target intake and configuration.
2. Multi-stage scanning workflow including recon, crawling, analyzer checks,
vulnerability testing, and result aggregation.
3. Persistent storage of scan metadata, findings, and related entities in a relational
database model.
4. Asynchronous worker-based execution and queue-backed processing.
5. Real-time scan progress updates and post-scan reporting interfaces.
6. AI-assisted chatbot workflows for navigation and vulnerability-context interaction.
7. Administrative interfaces for system-level operational visibility.
### 1.6.2 Explicit Limitations
1. The system is specialized for web application security assessment and does not
claim full host-hardening or endpoint-security coverage outside web-relevant
surfaces.
2. AI outputs are assistive and advisory; they do not constitute autonomous exploit
execution authority or guaranteed remediation correctness.

3. External tool behavior may vary by environment and runtime dependencies; robust
orchestration reduces but does not eliminate this variability.
4. Performance outcomes depend on target complexity, network conditions, and active
scan configuration depth.
5. The project emphasizes applied engineering integration and platform design over
formal vulnerability research novelty.
### 1.6.3 Boundary Clarification
The thesis documents the platform as a production-oriented engineering system rather
than a certification-grade security guarantee. Findings produced by SafeWeb-AI are
intended to support defensive decision-making and security operations, not to replace
comprehensive human-led penetration testing in all contexts.
## 1.7 Thesis Organization
The remainder of this thesis is organized to mirror the engineering lifecycle.
Chapter 2 presents the theoretical and practical background, including web security
fundamentals, OWASP framing, existing tool ecosystems, AI in cybersecurity, and the
specific research gap that motivates SafeWeb-AI.
Chapter 3 formalizes system analysis with stakeholder definitions, functional and non-
functional requirements, use-case perspective, process logic, sequence/activity
interpretations, and risk constraints.
Chapter 4 details architecture and design, including layered decomposition, subsystem
responsibilities, data architecture, security architecture, schema rationale, and
deployment-level structure.
Chapter 5 focuses on UI/UX design strategy, user journeys, interface organization, design
principles, and responsiveness.
Chapter 6 documents frontend implementation patterns, including routing, authentication
behavior, scan UI workflow, result rendering, and resilience patterns.
Chapter 7 describes backend implementation, API domains, access control logic,
orchestration pathways, validation behavior, and defensive controls.
Chapter 8 provides the deep technical core of the scanning engine, from orchestration and
recon through verification, correlation, scoring, and report generation.
Chapter 9 explains AI and ML integration, covering LLM usage boundaries, context
injection, prompt strategy, and model usage roles.
Chapter 10 addresses cloud infrastructure and DevOps strategy, including deployment
architecture, operational scaling, observability, and hardening.
Chapter 11 presents testing and evaluation methodology across unit, integration, security,
and reliability perspectives.

Chapter 12 discusses outcomes and limitations with balanced interpretation.
Chapter 13 concludes the work, summarizes contributions, and defines a practical future
roadmap.
References and appendices provide source traceability, expanded technical tables, and
supporting artifacts.

# Chapter 2: Background and Literature Review
The literature perspective in this chapter is aligned with OWASP standards, tool
documentation, and AI-in-cybersecurity research, with references spanning web testing
methodology, scanner ecosystems, and intelligent-assistance boundaries [1], [2], [3], [30],
[31], [32], [33], [34], [35], [36], [37], [47], [49], [50], [60].
The comparative framing is summarized through Table 2.1, Table 2.2, and Table 2.3 in the
final formatted edition.
## 2.1 Web Application Security Fundamentals
Web application security is fundamentally concerned with preserving confidentiality,
integrity, and availability in software systems that interact with untrusted input over
public or semi-public networks. The risk model differs from traditional perimeter-centric
models because web applications continuously expose parsing logic, session state, and
business workflows to remote actors. In modern architectures, this exposure extends
beyond a single web server to include API gateways, browser-side execution contexts,
cloud resources, and third-party service dependencies.
At a system level, security weaknesses in web applications can be understood as failures in
one or more control planes:
1. Identity and trust establishment, where user or service identity is incorrectly
verified.
2. Input and data handling, where untrusted data reaches sensitive execution paths
without robust validation or contextual encoding.
3. Authorization and policy enforcement, where access decisions are incomplete,
inconsistent, or bypassable.
4. Configuration and operational hardening, where secure defaults are missing or drift
over time.
5. Observability and incident readiness, where insecure events are neither detected
nor traceable.
### 2.1.1 Attack Surface Expansion in Modern Web Systems
Attack surface is not only the set of visible URLs. It is the aggregate of all reachable state
transitions that can influence privileged behavior or sensitive data. In practical terms,
attack surface now includes:
• Browser routes and dynamic client-side rendering paths.
• API endpoints and hidden parameters discovered through traffic analysis or
crawling.
• Authentication and token refresh workflows.
• File upload and content processing channels.
• Outbound integration paths that may enable server-side request forgery.
• Build and deployment interfaces when exposed via misconfiguration.

Because this surface is dynamic, static point-in-time audits are often insufficient. Effective
defensive practice requires continuous and repeatable scanning workflows.
### 2.1.2 Authentication and Session Risks
Authentication controls are frequently undermined by weak credential policies, misapplied
token lifecycles, inconsistent multi-factor checks, and insecure session invalidation. Token-
based architectures improve scalability, but they create new operational challenges: secure
storage, refresh token rotation, replay resistance, and revocation consistency.
Session risks are not restricted to stolen cookies. They include predictable token
identifiers, missing token binding assumptions, weak logout semantics, and race conditions
in refresh workflows. A robust security platform must test these flows under realistic
request sequencing, not only through isolated endpoint checks.
### 2.1.3 Injection-Class Weaknesses
Injection vulnerabilities remain among the highest-impact classes in web security because
they convert data channels into control channels. SQL injection can compromise data
confidentiality and integrity; command injection can escalate to host-level compromise;
template injection can break execution boundaries in server-side rendering engines; and
cross-site scripting can compromise user sessions and browser trust assumptions.
The complexity of modern applications introduces hybrid injection patterns where payload
impact depends on chained behavior across application layers. This reinforces the need for
contextual scanning and evidence-based confirmation.
### 2.1.4 Access Control and Business Logic Failures
Authorization defects frequently arise even in systems with strong authentication. Insecure
direct object reference, missing ownership checks, and privilege confusion across API
versions are common examples. Business logic flaws further complicate detection because
they may not violate syntax or protocol specifications while still enabling unauthorized
outcomes.
Traditional scanners can miss such conditions unless they incorporate stateful workflows,
parameter relationship analysis, and role-context awareness.
### 2.1.5 Misconfiguration and Exposure Risks
Security misconfiguration remains a persistent source of compromise due to incomplete
hardening and deployment drift. Missing security headers, weak TLS posture, permissive
CORS policies, exposed debugging endpoints, and publicly accessible storage buckets all
represent practical exploitation vectors. Misconfiguration issues are often easier to fix than
deep code flaws, but they require reliable detection and clear reporting.
## 2.2 OWASP Top 10 Context
The OWASP Top 10 serves as a high-level risk taxonomy rather than a complete testing
methodology. It is valuable in this thesis as a framing mechanism for risk communication,

requirement prioritization, and vulnerability class coverage mapping. SafeWeb-AI aligns its
scanning and reporting logic with OWASP-oriented categories to improve interpretability
for practitioners and evaluators.
### 2.2.1 Why OWASP Framing Is Useful
OWASP taxonomy provides three practical advantages:
1. Common language across developers, security engineers, and management
stakeholders.
2. Prioritization anchor for severity and remediation planning.
3. Benchmarking baseline for coverage claims in academic and operational contexts.
### 2.2.2 OWASP as a Boundary, Not a Ceiling
While useful, OWASP Top 10 does not fully capture all practical vulnerability classes
encountered in modern environments. Categories such as race conditions, advanced API
abuse, cloud storage exposure, and specialized protocol misuse may require broader tester
sets. SafeWeb-AI therefore uses OWASP framing but extends actual tester coverage beyond
only ten categories.
## 2.3 Existing Security Tools
The web security ecosystem includes mature commercial suites, open-source assessment
frameworks, and focused specialist tools. Each category contributes unique strengths but
also introduces integration and interpretation challenges when used independently.
### 2.3.1 Integrated Security Testing Suites
Burp Suite is widely adopted in professional penetration testing for interception, manual
testing augmentation, and extension-based workflows. Its depth is strong for analyst-
driven assessments, but effective usage depends heavily on practitioner expertise and
manual process rigor.
Acunetix and similar commercial scanners provide automated vulnerability detection with
broad signatures and enterprise reporting capabilities. Their strengths include usability
and standardized output pipelines, but organizations still face triage overhead and may
require complementary tooling for deep contextual testing.
Emerging AI-assisted coding and security assistants, including tools often discussed in
developer workflows (for example AI coding assistants and AI security review services),
can accelerate interpretation and remediation drafting. However, these tools are assistive
layers and do not replace deterministic scanner verification.
### 2.3.2 Reconnaissance and Asset Discovery Tools
Nmap remains foundational for network and service-level discovery. Subfinder and Amass
are widely used for subdomain enumeration and asset expansion. These tools are highly

valuable in early scan phases, but they produce heterogeneous output formats and
confidence levels that require normalization.
### 2.3.3 Vulnerability-Focused Probing Tools
SQLMap provides deep automation for SQL injection testing under suitable conditions.
Dalfox targets cross-site scripting discovery with payload strategies and response analysis.
Nuclei offers template-driven scanning across broad vulnerability signatures and
misconfiguration classes.
These tools are operationally effective but are strongest when orchestrated by a parent
system that manages scope, rate control, evidence handling, and deduplication.
### 2.3.4 Tool-Level Strengths and Limitations
Tool Family Strength Limitation in Isolation
Manual-interactive suites High analyst control and
depth
Low scalability, operator-
dependent consistency
Automated commercial
scanners
Rapid baseline detection and
reporting
False-positive triage
overhead, black-box
assumptions
Recon tools Strong attack-surface
expansion
Output fragmentation,
confidence variability
Exploit-focused testers Deep testing for specific
classes
Narrow scope, integration
burden
Template-based scanners Broad rule-driven coverage Context sensitivity and
validation gaps
The key literature insight is that tool diversity is beneficial, but unmanaged diversity
creates workflow fragmentation.
## 2.4 Existing Security Platforms
Security platforms can be broadly grouped into four operational models:
1. Manual platform-centric workflows (analyst-driven suites).
2. Automated scanner-centric workflows (single-engine products).
3. Hybrid CI/CD security pipelines (integrated in DevSecOps tooling).
4. Extended Attack Surface Management and vulnerability posture platforms.
### 2.4.1 Why Single-Mode Platforms Are Often Insufficient
Single-mode approaches struggle in at least one of the following dimensions:
• Coverage depth across heterogeneous vulnerability classes.
• Operational scalability for asynchronous large scans.
• Cross-stage finding correlation and confidence scoring.

• Context-aware explanation suitable for mixed-experience teams.
As a result, engineering teams often compose layered workflows manually, which increases
operational complexity and raises maintenance costs.
### 2.4.2 Platform Design Implications
The literature and field practice both indicate that practical platforms should combine:
1. Multi-phase acquisition and testing logic.
2. Deterministic signal generation.
3. Verification and confidence adjustment.
4. Clear risk communication.
5. Integration-ready interfaces for users and administrators.
SafeWeb-AI is designed to satisfy these principles in a single orchestrated architecture.
## 2.5 AI in Cybersecurity
AI usage in cybersecurity is most effective when treated as assistive reasoning rather than
authoritative control. For web security assessment platforms, AI can augment human and
deterministic logic in five areas: triage prioritization, explanation generation, strategy
support, remediation drafting, and interaction simplification.
### 2.5.1 AI for Triage and Prioritization
When scanners produce large finding volumes, teams require prioritization mechanisms
beyond severity labels. AI-supported ranking can incorporate context signals such as
endpoint criticality, exploitability indicators, and evidence completeness. However, AI
ranking should not overwrite deterministic evidence and must remain explainable.
### 2.5.2 AI for Security Explanation
Many security outputs are technically accurate but operationally opaque to non-specialists.
AI can transform raw findings into role-aware explanations, helping developers understand
impact, root cause hypotheses, and practical remediation direction.
### 2.5.3 AI for Attack Strategy Assistance
In scanning workflows, AI can support attack-surface interpretation and testing sequence
recommendations. This is particularly useful for complex targets where endpoint
relationships and technology fingerprints affect test prioritization.
### 2.5.4 AI for False-Positive Reduction
AI components can contribute confidence scoring by analyzing response patterns,
historical context, and evidence consistency. Yet false-positive reduction should remain a
composite process that includes deterministic verification and conservative decision
thresholds.

### 2.5.5 AI Safety in Offensive-Security-Adjacent Contexts
AI integration in security platforms introduces risks:
• Prompt injection attempts through untrusted scan content.
• Overconfident hallucinated remediation guidance.
• Boundary violations if model instructions are weak.
A safe architecture therefore requires explicit tool-call boundaries, policy-constrained
prompts, context sanitization, and refusal behavior for unsafe or out-of-scope requests.
## 2.6 Research Gap
The reviewed literature and platform landscape reveal a practical gap at the intersection of
automation, orchestration, and interpretability.
### 2.6.1 Identified Gap Dimensions
1. Workflow integration gap: Many tools are strong individually but weakly unified in
end-to-end operational platforms.
2. Verification gap: Detection outputs are often not followed by structured
confirmation pipelines.
3. Explainability gap: Scanner outputs may be dense and difficult for mixed teams to
action quickly.
4. Scalability gap: Manual-heavy processes do not sustain continuous security
assessment at scale.
5. Documentation gap in academic projects: Student systems often present prototypes
without full lifecycle analysis from requirements through deployment and
evaluation.
### 2.6.2 Gap Addressed by SafeWeb-AI
SafeWeb-AI targets this gap by combining:
• Multi-phase scanner orchestration.
• Asynchronous distributed execution.
• Structured vulnerability data model and risk scoring.
• AI-assisted but bounded remediation support.
• Full system analysis and design documentation suitable for academic defense and
engineering handover.
## 2.7 Comparison Matrix
To contextualize SafeWeb-AI against common operational approaches, Table 2.3 compares
four assessment modes.
### 2.7.1 Comparative Dimensions
The matrix evaluates each mode across eight dimensions:

1. Coverage breadth.
2. Verification support.
3. Operational scalability.
4. False-positive handling.
5. Contextual explanation quality.
6. Integration overhead.
7. Governance readiness.
8. Suitability for continuous assessment.
### 2.7.2 Comparative Matrix
Dimension
Manual
Penetration
Testing
Conventional
Automated
Scanner
Generic AI-
Assisted
Scanning Utility SafeWeb-AI
Coverage
breadth
Medium to High
(analyst
dependent)
Medium to High
(template/rule
dependent)
Medium (often
wrapper-level)
High (multi-
phase + tool
orchestration)
Verification
support
High (expert
judgment)
Low to Medium Medium High
(verification +
scoring
pipeline)
Operational
scalability
Low Medium Medium High (async
workers +
queueing)
False-positive
handling
Medium to High Low to Medium Medium Medium to High
(ensemble +
evidence logic)
Contextual
explanation
Medium (report
writer
dependent)
Low to Medium Medium to High High (scan-
aware assistant
layer)
Integration
overhead
High Medium Medium Low to Medium
(integrated
platform)
Governance
readiness
Medium Medium to High Medium High (role-
aware platform
model)
Continuous
assessment fit
Low to Medium Medium Medium High
### 2.7.3 Interpretation
The matrix does not claim that SafeWeb-AI replaces expert manual testing. Instead, it
indicates that SafeWeb-AI is designed to close operational gaps between coverage,
orchestration, and actionability. The system is best viewed as a force multiplier for

defensive security operations: it increases repeatability and visibility while preserving
deterministic evidence pathways.
## 2.8 Chapter Summary
This chapter established the conceptual and practical foundation for SafeWeb-AI. It
reviewed core web application security risk dimensions, justified OWASP-based framing,
analyzed existing tool and platform categories, and discussed the role of AI as an assistive
cybersecurity component. The chapter then identified a specific research and engineering
gap: the need for a unified system that combines scalable scan orchestration, confidence-
oriented finding processing, and context-aware guidance under a defensible architecture.
Chapter 3 builds on this foundation by formalizing the system analysis perspective,
including stakeholders, requirements, use cases, process logic, and operational constraints.

# Chapter 3: System Analysis
System analysis decisions in this chapter follow structured requirements and UML-
oriented analysis practice, mapped to secure web platform implementation evidence and
project documentation [7], [8], [9], [14], [15], [60], [61].
This chapter is read alongside Figure 3.1 through Figure 3.6 and Table 3.1 through Table
## 3.5 for complete analysis traceability.
## 3.1 Stakeholders
System analysis begins with identifying all parties who interact with, depend on, or govern
the platform. SafeWeb-AI is not a single-user utility; it is a multi-role cybersecurity system
with operational, administrative, and academic accountability dimensions.
### 3.1.1 Primary Stakeholders
1. Security analysts and end users. These users configure scan targets, monitor
execution progress, review vulnerabilities, export reports, and consume
remediation guidance. Their priorities are coverage, clarity, confidence, and
operational efficiency.
2. Application developers. Developers consume scan findings and remediation
recommendations to improve code quality and reduce vulnerability recurrence.
They require finding evidence, severity context, and actionable mitigation guidance.
3. Platform administrators. Administrators manage user lifecycle, monitor scan
operations, review system alerts, handle policy-level settings, and supervise
resource usage. Their priorities include governance, reliability, and platform health.
4. DevOps and infrastructure maintainers. This stakeholder group ensures deployment
health, worker availability, queue stability, data durability, and observability. Their
priorities are scalability, uptime, and secure operations.
5. Academic supervisors and evaluators. In a graduation context, supervisors assess
methodological rigor, architecture validity, implementation traceability, and testing
credibility.
### 3.1.2 Secondary Stakeholders
1. Organizational decision-makers who rely on report summaries for security posture
awareness.
2. Compliance and audit roles who require traceable findings and repeatable
assessment workflows.
3. Future engineering teams that may extend the platform.

### 3.1.3 Stakeholder Responsibility Matrix
Stakeholder Core Responsibilities Primary Success Criteria
End User / Analyst Submit targets, run scans,
review and export results
Accurate findings, clear
progress, useful reports
Developer Fix vulnerabilities and
validate remediation
Actionable evidence and
remediation quality
Administrator Govern users, monitor
operations, handle settings
Stable operations and policy
compliance
DevOps Maintainer Maintain deployment
reliability and scaling
Uptime, observability, queue
and worker health
Academic Supervisor Evaluate design and
implementation maturity
Technical rigor and
reproducibility
## 3.2 Functional Requirements
Functional requirements define what the platform must do from a user-facing and system-
facing perspective. The SafeWeb-AI requirement set was derived from workflow analysis,
architecture artifacts, and implemented module boundaries.
### 3.2.1 Authentication and Identity Management Requirements
• FR-01: The system shall support user registration with identity profile creation.
• FR-02: The system shall support credential-based login and token issuance.
• FR-03: The system shall support token refresh workflows for session continuity.
• FR-04: The system shall support secure logout and token invalidation pathways.
• FR-05: The system shall support optional two-factor authentication setup and
verification.
• FR-06: The system shall support session visibility and API key management for
authenticated users.
### 3.2.2 Scan Lifecycle Requirements
• FR-07: The system shall allow authenticated users to submit web targets for
scanning.
• FR-08: The system shall validate target format and scope boundaries before scan
execution.
• FR-09: The system shall create scan records with traceable lifecycle states.
• FR-10: The system shall dispatch scan jobs asynchronously to worker
infrastructure.
• FR-11: The system shall execute reconnaissance, crawling, analyzer checks, and
vulnerability tests as a coordinated pipeline.

• FR-12: The system shall persist findings, evidence, status transitions, and phase
timing artifacts.
• FR-13: The system shall provide live scan progress updates during execution.
• FR-14: The system shall support scan completion, failure handling, and rescan
operations.
### 3.2.3 Vulnerability Management Requirements
• FR-15: The system shall present vulnerabilities with severity, category, affected
URL, and evidence.
• FR-16: The system shall support filtering and structured review of finding sets.
• FR-17: The system shall support false-positive confidence handling and verification
metadata.
• FR-18: The system shall compute and expose a security score derived from severity-
weighted deductions.
• FR-19: The system shall support report export for completed scans.
### 3.2.4 AI Assistant Requirements
• FR-20: The system shall provide a conversational assistant for scan-aware guidance.
• FR-21: The assistant shall support function-bound actions such as scan initiation
status checks and export assistance.
• FR-22: The assistant shall incorporate recent scan context and prior conversation
context where permitted.
• FR-23: The assistant shall apply scope and safety controls for cybersecurity-
sensitive prompts.
### 3.2.5 Administrative and Governance Requirements
• FR-24: The system shall provide administrative dashboards for user and scan
oversight.
• FR-25: The system shall support management of system alerts and selected
platform settings.
• FR-26: The system shall provide role-aware access control between standard and
administrative operations.
### 3.2.6 Scheduling and Integration Requirements
• FR-27: The system shall support scheduled scan configuration for recurring
assessments.
• FR-28: The system shall support webhook-related entities for event-oriented
integration workflows.
• FR-29: The platform shall maintain compatibility with external tool wrappers and
graceful degradation behavior when specific binaries are unavailable.

### 3.2.7 Functional Requirement Catalog
Req ID Functional Requirement Priority
FR-01 to FR-06 Authentication and identity
management
High
FR-07 to FR-14 Scan lifecycle execution and
tracking
High
FR-15 to FR-19 Vulnerability review and
reporting
High
FR-20 to FR-23 AI assistant operations Medium to High
FR-24 to FR-26 Administrative governance High
FR-27 to FR-29 Scheduling and ecosystem
integration
Medium
## 3.3 Non-Functional Requirements
Non-functional requirements define quality constraints and operational characteristics. For
SafeWeb-AI, these requirements are essential because security platforms must remain
reliable under variable workloads and partially unreliable dependencies.
### 3.3.1 Performance Requirements
• NFR-01: The platform shall provide responsive UI interactions for scan creation and
result browsing.
• NFR-02: API endpoints shall support practical response times under expected
concurrent usage.
• NFR-03: Asynchronous scan execution shall prevent long-running operations from
blocking interactive sessions.
### 3.3.2 Reliability and Availability Requirements
• NFR-04: The platform shall preserve scan state consistency across lifecycle
transitions.
• NFR-05: Tool-level failures shall not cause catastrophic platform failure for the
entire scan workflow.
• NFR-06: The system shall support recoverable behavior for transient errors.
### 3.3.3 Scalability Requirements
• NFR-07: The architecture shall support horizontal scaling through worker-based
parallelization and queue-backed job distribution.
• NFR-08: Storage and query design shall support growth in historical scan records
and finding volume.

### 3.3.4 Security Requirements
• NFR-09: Access control boundaries shall be enforced for role-specific operations.
• NFR-10: Sensitive authentication artifacts shall be handled through secure token
lifecycles and session controls.
• NFR-11: Input handling across user-supplied fields shall enforce validation and
defensive error handling.
• NFR-12: AI interaction shall be constrained by policy-oriented guardrails.
### 3.3.5 Usability and Explainability Requirements
• NFR-13: Security findings shall be presented with interpretable severity and
evidence context.
• NFR-14: Progress and phase states shall be understandable to both specialists and
mixed-experience teams.
### 3.3.6 Maintainability and Modularity Requirements
• NFR-15: Scanner subsystems (recon, crawler, analyzers, testers, integrations) shall
remain modular for extension.
• NFR-16: API and frontend layering shall permit independent maintenance without
full-system rewrites.
### 3.3.7 Auditability Requirements
• NFR-17: Scan lifecycle actions and resulting artifacts shall be persistently traceable.
• NFR-18: Administrative actions and system alerts shall be reviewable.
### 3.3.8 NFR Summary
NFR Category Requirement Focus Target Outcome
Performance Responsiveness and async
processing
Practical user experience
under load
Reliability Graceful degradation and
recoverability
Stable operations despite
tool variance
Scalability Worker and queue
expansion
Growth-ready execution
model
Security Auth boundaries and safe
processing
Reduced platform abuse risk
Usability Clear findings and status
visibility
Faster triage and
remediation action
Maintainability Modularity and separation
of concerns
Easier long-term evolution
Auditability Persistent trace and
reviewability
Governance and
accountability support

## 3.4 Use Case Analysis
Use-case analysis bridges requirements to concrete actor behavior.
### 3.4.1 Core Actor Set
• Actor A1: Authenticated User
• Actor A2: Administrator
• Actor A3: System Scheduler / Background Worker
### 3.4.2 Primary Use Cases
1. UC-01 Register and authenticate. The user creates an account, logs in, and obtains
authenticated access to the platform.
2. UC-02 Configure and start scan. The user submits a target and scan parameters. The
system validates and queues the scan.
3. UC-03 Monitor live scan progress. The user observes phase transitions and status
updates while the scan executes asynchronously.
4. UC-04 Review vulnerabilities and evidence. The user inspects findings, severity
labels, affected assets, and evidence records.
5. UC-05 Export report artifacts. The user requests structured report outputs for
downstream workflow usage.
6. UC-06 Request AI-assisted guidance. The user interacts with the chatbot for
contextual explanations and permitted actions.
7. UC-07 Perform administrative oversight. The administrator reviews aggregate
system operations and handles governance tasks.
### 3.4.3 Use Case Detailing Example: UC-02 Configure and Start Scan
Preconditions: - User is authenticated. - Target input is provided.
Main flow: 1. User submits target and selected depth/scope configuration. 2. System
validates input format and policy constraints. 3. System creates scan record with initial
lifecycle state. 4. System dispatches asynchronous job to worker queue. 5. System returns
scan identifier and initial status.
Postconditions: - Scan exists in persistent store. - Worker can begin execution without
additional user blocking.
Alternative flows: - Invalid target format -> validation error response. - Permission issue ->
authorization rejection. - Dispatch failure -> controlled failure state with error message.

## 3.5 Business Logic
Business logic in SafeWeb-AI is built around a stateful scan lifecycle with clear transitions
and artifact generation behavior.

### 3.5.1 User-Centric Operational Logic
From user perspective, workflow follows:
1. Identity establishment (register/login).
2. Target submission and scan configuration.
3. Background execution with live visibility.
4. Findings review and prioritization.
5. Report export and remediation follow-up.
6. Optional chatbot-guided interpretation.
This sequence is intentionally designed to reduce cognitive switching. Users move from
intent (scan target) to decision support (validated findings and guidance) without leaving
the platform context.
### 3.5.2 System-Centric Operational Logic
From system perspective, logic follows:
1. Validate and normalize target input.
2. Persist scan state and configuration snapshot.
3. Queue and execute multi-phase scan orchestration.
4. Persist intermediate outputs and phase metadata.
5. Apply verification and confidence logic.
6. Calculate score and finalize scan record.
7. Expose structured outputs for UI and exports.
### 3.5.3 Business Rules
• BR-01: No scan can execute without valid target submission.
• BR-02: Scan lifecycle states must progress through controlled transitions.
• BR-03: Severity-based scoring deductions are deterministic and bounded.
• BR-04: AI assistant actions are constrained to registered function capabilities.
• BR-05: Administrative operations require elevated permissions.
## 3.6 Sequence Diagrams
SafeWeb-AI sequence artifacts provide timing and responsibility clarity across
components.
### 3.6.1 Authentication Sequence Interpretation
The authentication sequence shows user credential submission to API, credential
verification against persistent user records, session and token generation, and token return
to client. The sequence highlights separation between identity verification and session
persistence, supporting better control over token lifecycle management.

### 3.6.2 Scan Lifecycle Sequence Interpretation
The scan lifecycle sequence captures a distributed interaction model: user request to API,
API dispatch to queue, worker execution of recon and testing stages, result persistence, and
final delivery of status/results to user interfaces. The sequence confirms asynchronous
architecture and non-blocking design for long-running operations.

### 3.6.3 AI Chat Sequence Interpretation
The AI chat sequence shows user prompt submission, LLM request formation, optional
function-call invocation, tool/action result incorporation, and response delivery. This
model demonstrates the assistant as an orchestrated component with bounded
capabilities, not as a direct privileged executor.

### 3.6.4 Admin Operations Sequence Interpretation
The admin sequence models dashboard request, statistics query behavior, and aggregated
data response flow. It emphasizes operational monitoring and governance boundaries.

## 3.7 Activity Diagrams
Activity diagrams complement sequence views by modeling control flow and branch logic.
### 3.7.1 Authentication Activity
The authentication activity flow identifies key decision points such as credential validity
and second-factor requirements before session issuance. This representation is useful for
security review because it exposes failure branches and rejection states.

### 3.7.2 Scan Pipeline Activity
The scan pipeline activity model documents progression from target intake through recon,
crawling, attack-surface modeling, testing, verification, exploit-oriented support, scoring,
and completion. Branches are important where failure tolerance and retries are expected.
The activity perspective confirms that SafeWeb-AI is process-driven rather than endpoint-
driven.

### 3.7.3 Asynchronous Control Implications
Activity modeling also clarifies asynchronous behavior:
1. User-facing interaction can continue while workers process scan tasks.
2. Partial outputs can be persisted before full completion.
3. Error branches can be handled phase-by-phase rather than all-or-nothing.

## 3.8 Risk and Constraint Analysis
A realistic system analysis must include engineering risks and constraints that affect
operational trust.
### 3.8.1 Scanning Safety Risks
Risk: uncontrolled scan behavior may stress target systems or exceed acceptable
boundaries.
Mitigation direction: - Scope controls and target validation. - Rate-awareness and staged
testing patterns. - Defensive defaults in scan configuration.
### 3.8.2 Timeout and Long-Running Task Risks
Risk: scans on large or complex applications can exceed practical execution windows.
Mitigation direction: - Queue-backed asynchronous architecture. - Worker timeout controls
and resilient status handling. - Incremental persistence of intermediate results.
### 3.8.3 False Positive and Analyst Load Risks
Risk: high false-positive density can reduce usability and trust.
Mitigation direction: - Verification stage and confidence scoring. - Severity-based
prioritization. - Context-aware assistant explanations.
### 3.8.4 External Tool Dependency Risks
Risk: external wrappers may fail due to binary absence, version mismatch, or
environmental constraints.
Mitigation direction: - Graceful degradation model. - Tool health checks and wrapper
isolation. - Pipeline continuity even when selected tools fail.
### 3.8.5 Cloud and Operations Constraints
Risk: deployment environments impose resource quotas, network limits, and configuration
complexity.
Mitigation direction: - Layered architecture separation. - Observability and alerting
mechanisms. - Clear configuration boundaries for secrets and service endpoints.

### 3.8.6 Risk Register Summary
Risk ID Risk Description Impact Likelihood
Mitigation
Priority
R-01 Scope misuse or
unsafe scan
configuration
High Medium High
R-02 Long-running
task timeout
and partial
failure
Medium to High Medium High
R-03 False-positive
overload
Medium High High
R-04 External tool
execution
variability
Medium High High
R-05 Queue/worker
bottlenecks
under load
High Medium High
R-06 Misconfiguratio
n in deployment
environment
High Medium High
R-07 AI misuse or
unsafe prompt
behavior
Medium to High Medium High
## 3.9 Chapter Summary
This chapter translated SafeWeb-AI into an analyzable system artifact. It identified
stakeholder roles, formalized functional and non-functional requirements, defined key use
cases, and clarified business rules governing scan lifecycle behavior. It also interpreted the
platform’s sequence and activity artifacts to expose timing, branching, and asynchronous
execution characteristics. Finally, it documented major risks and constraints with
mitigation-oriented reasoning.
Chapter 4 builds directly on this analysis by presenting architecture and design rationale at
subsystem and deployment levels.

# Chapter 4: System Architecture and Design
The architecture rationale in this chapter is informed by systems design references, clean
architecture principles, data-intensive system practices, and implementation
documentation for the SafeWeb-AI platform [7], [9], [10], [11], [14], [15], [16], [17], [18],
[60], [61].
Architectural interpretation should be cross-read with Figure 4.1 through Figure 4.6 and
Table 4.1 through Table 4.4.
## 4.1 Architecture Overview
SafeWeb-AI is engineered as a layered cybersecurity platform where each layer contributes
a bounded responsibility while exchanging structured data through explicit interfaces. This
decomposition is intentional: vulnerability scanning is operationally complex, and tightly
coupled architectures quickly become fragile when adding new testers, external tools, or
deployment targets. The SafeWeb-AI architecture therefore emphasizes modular
composition, asynchronous execution, and traceable state transitions.
At a high level, the system can be represented as eight coordinated layers:
1. Frontend presentation layer.
2. Backend API and application services layer.
3. Asynchronous execution layer (queue and workers).
4. Scanning engine layer.
5. AI assistant and intelligence layer.
6. Persistence and storage layer.
7. External tooling and integration layer.
8. Cloud infrastructure and operations layer.

The layered model provides two architectural advantages. First, it supports separation of
concerns, allowing each team role (frontend, backend, AppSec, AI/ML, DevOps) to evolve
the platform without destabilizing unrelated modules. Second, it improves failure
containment: scanner tool failures, long-running tasks, or external dependency issues do
not directly collapse user-facing interaction paths.

### 4.1.1 End-to-End Flow Across Layers
A typical scan request traverses the architecture in the following sequence:
1. User submits target and scan configuration via frontend.
2. Backend validates request and persists initial scan state.
3. API dispatches asynchronous job to queue-backed worker execution.
4. Scanner orchestrator executes phased recon, crawling, analyzers, testers,
verification, and scoring.
5. Intermediate and final results are persisted in database and report storage.
6. Progress events are streamed back to frontend through live update channels.
7. User inspects findings and can request AI-assisted interpretation.
This flow demonstrates that user responsiveness is decoupled from scan execution
duration, which is essential in security scanning workloads where execution time is target-
dependent.

### 4.1.2 Layer Responsibility Matrix
Layer Primary Responsibility Key Outputs
Frontend User interaction, state
visualization, workflows
Scan requests, UI events,
report views
Backend API Validation, authorization,
orchestration control
API responses, queued jobs,
governed access
Async Queue/Workers Non-blocking scan execution Phase progress, persisted
intermediate artifacts
Scanning Engine Security assessment logic Findings, evidence, severity,
correlations
AI Layer Context-aware assistive
guidance
Explanations, action
suggestions, workflow
support
Persistence/Storage Durable scan records and
artifacts
Historical data, reports,
evidence retention
External Tools Specialized recon and
testing operations
Tool-specific scan signals
Cloud/Ops Hosting, scaling, monitoring,
security controls
Operational continuity and
observability

## 4.2 Component-Level Architecture
The component architecture translates the layered view into deployable and maintainable
subsystems.

### 4.2.1 React SPA Component
The frontend is implemented as a React 18 single-page application with route-level code
splitting. It handles authentication views, scan creation, real-time progress pages,
vulnerability result exploration, profile management, and admin pages. Frontend
responsibilities include:
• Capturing user intent through controlled forms and validated inputs.
• Managing session state with token-aware API calls.
• Rendering scan and finding state transitions in a low-latency interface.
• Exposing conversational entry points for AI assistance.

The frontend is intentionally thin with respect to security decision logic; authoritative
enforcement remains in backend services.
### 4.2.2 Django REST API Component
The backend provides domain APIs for authentication, scan management, chatbot
interaction, dashboard analytics, and administration. It serves as the policy gatekeeper for:
• Input validation and scope normalization.
• Permission checks and role boundary enforcement.
• Stateful lifecycle control for scans.
• Serialization and persistence coordination.

Its architecture is organized around multiple Django apps with focused domain ownership
(accounts, scanning, chatbot, ml, admin_panel, learn).
### 4.2.3 Celery Worker Component
Security scanning is executed in Celery workers to avoid blocking synchronous API
requests. Worker responsibilities include:

• Running long-lived scan tasks and phase transitions.
• Invoking external tool wrappers and internal testers.
• Persisting partial state and progress events.
• Handling recoverable errors with controlled failure semantics.

This component enables concurrency and scale-out behavior by increasing worker pools
independently from API instances.

### 4.2.4 Redis Queue/Broker Component
Redis acts as task broker and cache support layer. It decouples API request handling from
execution throughput. Queue semantics offer temporal buffering under burst workloads
and support stable task dispatch under variable scan complexity.

### 4.2.5 PostgreSQL Data Component
PostgreSQL persists core entities: users, scans, vulnerabilities, chat sessions/messages, API
keys, scheduling metadata, and reporting artifacts. JSON/JSONB-like flexible fields are used
in scan-related records to capture evolving result structures while retaining relational
integrity for critical joins.

### 4.2.6 Blob/Object Storage Component
Report and evidence artifacts are stored outside the primary relational store to keep
transactional tables performant and to support export-oriented workflows. This separation
also improves archival and lifecycle management.

### 4.2.7 AI Assistant Component
The AI component is integrated as a constrained assistant with function-call-based action
hooks. It supports scan-context retrieval, status explanation, and remediation-oriented
conversation while operating within guardrails. It is intentionally non-authoritative for
core vulnerability truth.

### 4.2.8 External Security Tool Integration Component
SafeWeb-AI integrates multiple specialized tools (reconnaissance, endpoint discovery,
template scanning, injection probing, CMS checks, TLS analysis, cloud exposure checks).
Wrappers normalize invocation behavior and output handling to ensure orchestrator
interoperability.

### 4.2.9 Component Interaction Summary
Component Consumes Produces
React SPA API responses, progress
events
Scan requests, auth flows,
user actions
Django API User requests, tokens, DB
records
Validated responses, task
dispatch
Celery Workers Queue tasks, config context Findings, status updates,
artifacts
Redis Dispatch commands Buffered execution tasks
PostgreSQL Domain writes/reads Persistent lifecycle and
finding records
Blob Storage Export payloads Durable report files
AI Assistant User prompts, scan context Guided responses and
function calls
Tool Wrappers Orchestrator instructions Security signals and raw
evidence

## 4.3 Internal Scanner Architecture
The scanning engine is the technical core of SafeWeb-AI. It is designed as a phased pipeline
to preserve both logical ordering and extensibility.

### 4.3.1 Orchestration Core
The orchestrator manages scan state transitions, phase sequencing, timing capture,
progress publication, and exception boundaries. Rather than running all modules blindly, it
coordinates dependencies between phases. For example, recon outputs can influence
crawling scope, and crawling outputs inform tester target sets.
### 4.3.2 Reconnaissance Engine
Reconnaissance is implemented as multi-wave acquisition to balance breadth and
relevance:
1. Independent discovery wave (DNS, WHOIS, certificates, baseline asset probes).
2. Response-dependent wave (technology fingerprinting, headers/cookies/CORS
intelligence).
3. Cross-module enrichment wave (content discovery, parameter discovery, API
surface hints).

4. Analytics wave (risk-oriented aggregation and prioritization cues).

This sequencing prevents premature heavy testing and improves downstream targeting
quality.
### 4.3.3 Crawling Engine
The crawler combines link traversal and dynamic rendering support to enumerate
endpoint candidates beyond static URL lists. It targets forms, query-bearing routes, and
JavaScript-discovered paths to improve coverage in single-page and API-driven
applications.

### 4.3.4 Analyzer Engine
Analyzer modules inspect passive and semi-active security posture indicators, including:
• Security header quality.
• TLS/SSL configuration characteristics.
• Cookie security attributes.
• Policy and exposure signals relevant to broader testing strategy.

### 4.3.5 Vulnerability Tester Framework
The tester layer is category-based and modular, allowing individual testers to inherit
common execution behavior while implementing class-specific logic. This supports
maintainability and allows new tester insertion with minimal changes to orchestrator core
logic.

### 4.3.6 Evidence Verification Layer
A key architectural distinction is the explicit verification stage. Findings from testers and
tools are not treated as equally confident by default. Verification modules re-check
conditions and attach confidence metadata to reduce analyst triage burden.

### 4.3.7 Correlation and Chaining Layer
Correlation modules attempt to connect individual findings into attack narratives and chain
candidates. This improves prioritization by highlighting compounding risk rather than
isolated vulnerability counts

### 4.3.8 Risk Scoring and Reporting Layer
The scoring subsystem computes a bounded security score from severity-weighted
deductions. Reporting modules transform persisted outputs into user-facing and export-
friendly formats.

### 4.3.9 Scanner Layered Internal View
Scanner Subsystem Purpose Dependence
Orchestrator Phase sequencing and
lifecycle control
None (entry control plane)
Recon Target intelligence
acquisition
Initial target validation
Crawler Endpoint and interaction
discovery
Recon scope guidance
Analyzers Baseline posture assessment Reachable target context
Testers Active vulnerability probing Crawled assets and
parameters
Verification Confidence refinement Raw findings from
testers/tools
Correlation Multi-finding risk synthesis Verified findings
Scoring/Reporting Decision support and export Final processed finding set

## 4.4 Data Architecture
The data architecture must support both transactional integrity and flexible security
artifact capture. Scan pipelines generate heterogeneous outputs; strict rigid schemas alone
would limit adaptation, while fully unstructured stores would reduce queryability.
### 4.4.1 Persistence Model
SafeWeb-AI adopts a hybrid relational-plus-structured-document approach:
• Relational entities for identities, scan records, vulnerabilities, chat sessions, and
governance metadata.
• Structured JSON-style fields for recon and tester payloads where schema variability
is expected.
This design allows strong joins for dashboard and lifecycle operations while preserving
extensibility for evolving scanner modules.
### 4.4.2 Scan Data Lifecycle
1. Scan creation: record initialized with target, depth, and status.
2. Execution progression: phase artifacts written incrementally.
3. Finding production: vulnerability records created with evidence and severity.
4. Verification and scoring: confidence and score values updated.
5. Completion and export: reports generated and persisted.
6. Historical retention: records remain queryable for trend and comparison views.
### 4.4.3 Result Storage Strategy
Core scan and vulnerability metadata remain in relational tables. Heavy report artifacts and
export files are routed to object storage with references in report entities. This separation
preserves database performance and simplifies long-term retention strategy.
### 4.4.4 Queue and Cache Data Roles
Queue data is ephemeral and execution-oriented, while scan history is durable.
Architectural separation between queue broker and relational persistence prevents
accidental coupling between operational throughput and historical audit trails.
### 4.4.5 Data Integrity and Traceability
The architecture supports traceability via identifiers linking:
• User -> Scan
• Scan -> Vulnerability
• Scan -> Report
• ChatSession -> ChatMessage
• User -> APIKey and session records

This relational traceability is critical for governance, reproducibility, and academic
defensibility.
## 4.5 Security Architecture
Security architecture in SafeWeb-AI is designed as a layered control model where identity,
access, processing, and operational controls reinforce each other.
### 4.5.1 Authentication Model
The platform uses token-based authentication workflows with refresh support, aligning
with stateless API scaling patterns while preserving controlled session handling semantics.
### 4.5.2 Authorization Boundaries
Role boundaries distinguish standard user operations from administrative operations.
Sensitive routes are protected by permission classes and role checks in API services.
### 4.5.3 Session and Token Handling
Session-related entities and token lifecycle controls support visibility and revocation-
oriented behavior. This reduces persistent session abuse risk and improves account
governance.
### 4.5.4 API Protection Controls
Security controls in API layer include:
• Input validation through serializers and request checks.
• Controlled error exposure.
• Permission enforcement for protected endpoints.
• Rate-aware defensive behavior for abuse reduction.

### 4.5.5 Scan Isolation and Safety
Scan execution is isolated in worker processes and bounded by orchestrator controls. Tool
failures are contained, and pipeline degradation is handled gracefully to reduce full-system
impact.

### 4.5.6 Auditability and Governance
Persistent scan records, session data, alerts, and admin domain entities provide a basis for
auditable operations and governance review.

### 4.5.7 Security Control Mapping
Security Dimension Control Approach
Identity Token-based authentication and user model
constraints
Authorization Role-aware permissions and endpoint
protection
Input Safety Serializer validation and controlled request
parsing
Execution Safety Worker isolation and bounded tool
invocation
Data Safety Structured persistence with bounded
exposure
Governance Admin panel entities and lifecycle
traceability
AI Safety Function-bounded assistant behavior and
scope controls
## 4.6 Database Design
Database design is a central architectural asset because scanning systems generate high-
volume, high-variability security artifacts. SafeWeb-AI uses a normalized core schema with
extensible fields for dynamic scan outputs.

### 4.6.1 Core Entity Groups
1. Identity and account entities.
• Users
• API keys
• user sessions
2. Scan lifecycle entities.
• Scans
• Vulnerabilities
• Auth configurations
• Scan reports
3. Operational entities.
• Scheduled scans
• Webhooks and webhook delivery records
• Scope definitions
• Multi-target scan metadata
• Discovered assets
4. Conversational intelligence entities.
• Chat sessions
• Chat messages
5. Administrative and learning entities.
• System alerts
• System settings
• Learning articles

### 4.6.2 Entity-Level Design Rationale
Users
Purpose: identity root for ownership, access control, and profile metadata. Key role: parent
entity for scans, API keys, sessions, and chat contexts.
Scans
Purpose: lifecycle anchor for each assessment. Key role: holds target, status, depth, score,
and scan-phase artifacts.
Vulnerabilities
Purpose: normalized findings repository. Key role: severity, category, affected location,
evidence, and confidence data.
API Keys
Purpose: controlled programmatic access support. Key role: key status and usage tracking.

Chat Sessions and Messages
Purpose: contextual AI interaction persistence. Key role: conversational traceability and
feedback capture.
Scheduled Scans
Purpose: recurring assessment automation. Key role: cron-like configuration and run
tracking.
Webhooks
Purpose: integration event transport metadata. Key role: target URL, event subscriptions,
activation state.
Scan Reports
Purpose: export artifact tracking. Key role: format, storage reference, generation metadata.
### 4.6.3 Relationship Logic
Critical relationships include:
• One user to many scans.
• One scan to many vulnerabilities.
• One user to many API keys/sessions.
• One chat session to many chat messages.
• One scan to many reports and discovered assets.
This model enables both operational queries (current scan state) and analytical queries
(historical trends by user/severity/category).

### 4.6.4 Database Design Table
Entity Primary Purpose Key Relationship
User Identity and ownership Parent for scans, keys,
sessions, chats
Scan Lifecycle container Parent for vulnerabilities
and reports
Vulnerability Finding record Child of scan
APIKey Programmatic access Child of user
UserSession Session governance Child of user
ChatSession AI conversation container Linked to user and optional
scan
ChatMessage Conversation step Child of chat session
ScheduledScan Recurring execution
metadata
Child of user
Webhook Event integration endpoint Child of user
ScanReport Export metadata Child of scan
DiscoveredAsset Recon-derived asset record Child of scan
Article Learning content Independent educational
domain

## 4.7 Class Diagram
The class model mirrors domain responsibilities and inheritance boundaries.

### 4.7.1 Domain Class Clusters
1. Account and identity classes.
2. Scan and finding classes.
3. Conversation and AI-context classes.
4. Administrative classes.
5. Learning center content classes.
### 4.7.2 Responsibility Distribution
Class responsibilities are intentionally cohesive:
• User-oriented classes own identity and access metadata.
• Scan classes own lifecycle and security output state.
• Messaging classes own chat transcript and assistant interaction artifacts.
This avoids anti-patterns where a single class aggregates unrelated concerns.
### 4.7.3 Object Model and Extensibility
The class model supports extension by composition and modular app boundaries. New
tester categories or integration entities can be introduced without modifying unrelated
identity or chat classes.
### 4.7.4 Diagram Interpretation Notes
The class diagram should be read as a domain communication artifact rather than an
exhaustive runtime object graph. It highlights ownership, cardinality, and responsibility
boundaries that shape maintainable implementation.
## 4.8 Deployment Architecture
SafeWeb-AI is documented as a cloud-deployed platform with managed services for API
hosting, frontend delivery, queueing, persistence, and observability.
### 4.8.1 Cloud Service Topology
Core deployment units include:
• Frontend hosting service for React SPA delivery.
• Backend application hosting for Django API.
• Managed PostgreSQL for relational persistence.
• Managed Redis for queue and cache operations.
• Blob/object storage for report artifacts.
• Monitoring stack for metrics and diagnostics.
• Secret management service for sensitive configuration.

### 4.8.2 Runtime Separation
Deployment strategy separates:
1. Request/response API workloads.
2. Background scan execution workloads.
3. Persistent data services.
4. Observability and operational controls.
This separation supports independent scaling and reduces coupled failure domains.
### 4.8.3 CI/CD and Environment Segmentation
The documented delivery model includes pipeline-based deployment and environment
separation (development, staging, production). This is critical for safe migration, rollout
control, and rollback readiness.
### 4.8.4 Operational Readiness Controls
Deployment architecture incorporates health checks, logging integration, and
infrastructure-level monitoring hooks to support incident triage and service quality
management.

## 4.9 Design Rationale
Architectural design choices in SafeWeb-AI are justified by workload characteristics,
security requirements, and maintainability objectives.
### 4.9.1 Why Layered Architecture
Layering provides clear boundaries between user interaction, business policy, execution,
and persistence. In security platforms, this clarity directly improves auditability and
incident analysis.
### 4.9.2 Why Asynchronous Scan Execution
Vulnerability scans are long-running and target-dependent. Synchronous execution would
degrade user experience and resource utilization. Queue-backed workers allow the
platform to remain responsive while handling heavy tasks.
### 4.9.3 Why Multi-Phase Scanning
A phased pipeline avoids naive all-at-once probing. Recon and crawling improve test
targeting; verification and correlation improve result quality; scoring improves
prioritization utility.
### 4.9.4 Why Hybrid Data Model
Security artifacts are partially structured and partially variable. Combining relational
integrity with flexible fields balances queryability and extensibility.

### 4.9.5 Why Bounded AI Integration
AI is used as an assistive component to improve interpretation and workflow guidance.
Core vulnerability truth remains anchored in deterministic scanning and verification logic.
This preserves trust and reduces over-reliance risk.
### 4.9.6 Why Modular Tool Wrappers
External security tools vary in output format and runtime requirements. Wrapper
abstraction normalizes invocation and facilitates graceful degradation when dependencies
are unavailable.

### 4.9.7 Design Trade-Off Summary
Decision Benefit Trade-Off
Layered architecture Maintainability and clarity Requires disciplined
interface design
Async workers Scalability and
responsiveness
Added operational
complexity
Multi-phase pipeline Better coverage and context Longer end-to-end scan
times
Verification stage Reduced false positives Additional compute and
logic overhead
AI assistive layer Better user interpretation Requires safety guardrails
Tool-wrapper abstraction Integration flexibility Wrapper maintenance
burden
## 4.10 Chapter Summary
This chapter formalized SafeWeb-AI as a complete architecture and design artifact. It
presented layered architecture, component interactions, scanner internal structure, data
and security architecture, entity-level database rationale, class-level responsibility
boundaries, cloud deployment model, and design decision trade-offs. The chapter
establishes a foundation for implementation-centric chapters by clarifying why the system
is structured the way it is and how each subsystem contributes to defensible cybersecurity
operations.
Chapter 5 builds on this architecture by focusing on user experience and interface design
decisions that translate technical capability into practical operational usability.

# Chapter 5: UI/UX Design
The UI/UX decisions presented in this chapter are grounded in human-centered design
principles, frontend implementation standards, and SafeWeb-AI interface architecture
artifacts [13], [19], [20], [21], [61].
The final thesis layout ties this chapter to Figure 5.1 through Figure 5.9 and Table 5.1
through Table 5.2.
## 5.1 UI/UX Goals
A cybersecurity platform can only create practical value if users can translate technical
outputs into security decisions with low friction. For SafeWeb-AI, UI/UX design is not
treated as cosmetic enhancement; it is an operational layer that affects analyst efficiency,
triage quality, and trust in scanner outcomes.
The UI/UX strategy is therefore built around the following goals:
1. Usability under technical complexity.
2. Clear information hierarchy for risk-first interpretation.
3. Low cognitive load during scan monitoring and finding review.
4. Continuous feedback during long-running operations.
5. Consistent interaction behavior across user and admin surfaces.
6. Responsive experience across desktop, tablet, and mobile contexts.
### 5.1.1 Security-First Usability
Unlike generic dashboards, security interfaces often present dense and high-stakes
information. If the interface obscures severity, evidence, or action options, users may miss
critical findings. SafeWeb-AI therefore prioritizes severity visibility, phase progress clarity,
and structured vulnerability cards/tables designed for fast triage.
### 5.1.2 Trust and Transparency
The platform communicates system state explicitly: queued, scanning, verifying, completed,
or failed. This transparency reduces uncertainty and helps users distinguish between
network delays, backend issues, and expected processing time.
### 5.1.3 Assisted Decision Flow
The conversational assistant is positioned as a workflow support channel that reduces
context switching. Instead of navigating multiple pages for every clarification, users can
request contextual explanations from the AI layer within the application flow.
## 5.2 Design Principles
SafeWeb-AI UI/UX implementation follows a principle-driven design system.

### 5.2.1 Consistency
The interface enforces consistent patterns for buttons, cards, badges, navigation, and
forms. Consistency shortens learning time and improves confidence in action outcomes.
Repeated interaction patterns are especially important in security systems where users
may operate under time pressure.
### 5.2.2 Hierarchy and Signal Emphasis
Visual hierarchy is tuned for security relevance:
• Severity and risk signals are elevated.
• Secondary metadata is grouped but visually subordinate.
• Primary user actions are predictable and prominently placed.
This supports rapid scanning of dense result pages.
### 5.2.3 Feedback and State Visibility
The design ensures immediate feedback for user actions and ongoing feedback for long-
running tasks. Loading states, progress indicators, and status chips communicate system
activity to reduce ambiguity.
### 5.2.4 Accessibility-Oriented Clarity
The interface adopts readable typography scales, sufficient contrast for key states, and
semantic grouping of information. While specialized accessibility audits may extend
further, baseline accessibility principles are embedded in component design.
### 5.2.5 Responsiveness and Adaptation
SafeWeb-AI supports desktop-first analytical workflows while maintaining functional
continuity on smaller devices. Responsive behavior focuses on preserving task completion
pathways rather than perfect feature symmetry across all screen sizes.
### 5.2.6 Trust-Building Visual Language
Cybersecurity products often rely on visual cues that signal precision and reliability.
SafeWeb-AI uses structured dark-theme aesthetics, accent-based status signaling, and
consistent iconography to reinforce professional trust without overwhelming visual noise.

### 5.2.7 Principles-to-Interface Mapping
Principle Interface Implication
Consistency Shared components and recurring layout
structure
Hierarchy Severity-first placement and progressive
detail reveal
Feedback Progress streams, status chips, action
confirmations
Accessibility Legible typography and contrast-conscious
states
Responsiveness Adaptive layout by breakpoint and priority
content ordering
Trust language Controlled color semantics and stable
interaction patterns
## 5.3 Information Architecture
Information architecture (IA) defines how users navigate from intent to outcome with
minimal confusion.
### 5.3.1 IA Domains
SafeWeb-AI IA is organized into the following domains:
1. Authentication domain.
2. Scanning domain.
3. Results and reporting domain.
4. AI assistance domain.
5. Profile and settings domain.
6. Administrative domain.
7. Learning and documentation domain.
This decomposition reflects task-centered navigation rather than purely technical module
grouping.
### 5.3.2 Route-Level Structure
The route architecture includes public pages, authenticated pages, and role-restricted
administrative pages. This not only supports user navigation but also mirrors security
boundaries in backend authorization logic.
### 5.3.3 Task Path Design
Typical IA flow for core user tasks:

• Login/Register -> Dashboard -> Start Scan -> Live Progress -> Results ->
Vulnerability Detail -> Export Report.
The key UX decision is maintaining continuity: each step naturally reveals the next action
without requiring users to reconstruct platform logic.
### 5.3.4 AI Assistance Placement
AI entry points are available in workflow-relevant contexts, enabling users to ask scan-
specific questions where interpretation burden is highest. This reduces cognitive load and
cross-page friction.
## 5.4 User Journey
User journeys represent behavior-level validation of IA and interaction design.
### 5.4.1 Journey A: First-Time Registration
1. User visits landing or registration page.
2. User provides identity credentials.
3. System validates and creates account.
4. User logs in and reaches dashboard.
UX objective: remove onboarding friction while preserving secure credential handling.
### 5.4.2 Journey B: Authentication and Access
1. Returning user submits credentials.
2. System authenticates and establishes session/token context.
3. User accesses protected routes.
UX objective: reliable session continuity and transparent error handling for invalid states.
### 5.4.3 Journey C: Running a Scan
1. User opens scan creation page.
2. User enters target and configuration choices.
3. Validation feedback confirms or rejects input.
4. Scan is queued and tracking interface opens.
UX objective: make complex scan configuration feel controlled and understandable.
### 5.4.4 Journey D: Monitoring Progress
1. User receives real-time phase updates.
2. UI presents transitions and completion indicators.
3. User can navigate while maintaining scan context.
UX objective: reduce uncertainty in long-running operations.
### 5.4.5 Journey E: Reviewing Findings
1. User opens results page after completion.

2. Findings are grouped and filterable by severity/category.
3. User drills down into evidence-rich details.
UX objective: accelerate triage and remediation planning.
### 5.4.6 Journey F: AI-Assisted Clarification
1. User opens chat widget or chat interface.
2. User asks vulnerability or workflow question.
3. Assistant returns context-aware response and allowed actions.
UX objective: turn dense security findings into understandable guidance.
### 5.4.7 Journey G: Report Export
1. User requests export from result context.
2. System generates artifact and returns downloadable output.
UX objective: support governance and communication workflows.
### 5.4.8 Journey Mapping Table
Journey Primary Actor Core Outcome
Registration New user Account creation and secure
onboarding
Authentication Returning user Protected access restoration
Scan initiation Analyst Valid target submission and
queued execution
Live monitoring Analyst Visibility into scan lifecycle
Findings review Analyst/Developer Prioritized vulnerability
interpretation
AI interaction Analyst/Developer Contextual explanation and
workflow support
Report export Analyst/Admin Artifact sharing and
documentation
## 5.5 Interface Screens
This section describes major interface groups and their operational purpose.
### 5.5.1 Onboarding and Authentication Screens
Login and registration screens provide direct, low-noise entry to secure workflows. Input
fields are structured for clarity, and error states communicate corrective action without
exposing sensitive backend details.

### 5.5.2 Dashboard Screen
The dashboard is an operational home view that summarizes scan activity and provides
rapid access to key actions. It balances high-level metrics with direct workflow entry
points.
### 5.5.3 Scan Configuration Screen
This screen captures target URL, depth/scope options, and scan initiation intent. Form
organization is optimized to reduce misconfiguration risk by keeping required fields visible
and optional controls contextual.
### 5.5.4 Live Progress Screen
The progress interface surfaces phase transitions, status markers, and real-time events. It
is built to maintain user trust during asynchronous execution.
### 5.5.5 Results Screen
Results are presented through sortable/filterable structures with severity cues, category
labels, and drill-down pathways. The design supports both quick overview and deep
analysis.
### 5.5.6 Vulnerability Detail Screen
Detailed view includes affected endpoint context, evidence, and remediation narrative. This
is the handoff surface between security analysis and engineering remediation.
### 5.5.7 AI Chat Interface
The chat surface enables question-driven exploration of scan context, status, and
remediation concerns. The interface is integrated into normal user flow rather than
positioned as a detached experimental feature.
### 5.5.8 Admin Panel Screens
Administrative views include user management, scan oversight, and system-level insights.
UI structure emphasizes governance and controlled operations.
## 5.6 Visual System
SafeWeb-AI uses a coherent visual system suited to cybersecurity dashboards.
### 5.6.1 Color System
The platform applies a dark primary foundation with accent colors for interaction and
status emphasis. Documented core color direction includes:
• Primary background: deep near-black tonal base.
• Accent green: used for positive and active state signals.
• Accent blue: used for informational highlights and navigation cues.

• Severity and alert colors: mapped to risk communication semantics.
Color use is functional, not decorative. It communicates system status and risk meaning.
### 5.6.2 Typography
Typography combines readability with technical tone. Distinct font roles are used for body
text, headings, and code-like technical elements. This supports scan readability and visual
rhythm in dense pages.
### 5.6.3 Components and Patterns
Reusable components include buttons, cards, badges, form controls, and feedback blocks.
Component variants are intentionally limited to maintain consistency and reduce user
confusion.
### 5.6.4 Status Indicators
Status indicators represent lifecycle states, severity classes, and operation outcomes. They
are central to reducing interpretation delay in security workflows.
### 5.6.5 Iconography and Motion
Icons support scanning and recognition speed. Motion, where used, is subtle and
purposeful (for example state transitions or reveal effects), avoiding distraction in
analytical tasks.
### 5.6.6 Visual System Summary
Visual Element Design Purpose
Dark thematic base Focus and reduced visual fatigue
Accent status colors Fast state and severity recognition
Structured typography Readability across dense security data
Card and badge system Modular information grouping
Icons and subtle animation Context reinforcement and interaction
feedback
## 5.7 Accessibility and Responsiveness
### 5.7.1 Accessibility Baseline
The interface strategy incorporates:
1. Clear text hierarchy and spacing.
2. Contrast-aware state rendering for critical indicators.
3. Predictable navigation and interaction locations.
4. Semantic grouping of related controls and outputs.

These practices support broader usability across user experience levels and varying
display conditions.
### 5.7.2 Responsive Design Strategy
SafeWeb-AI adopts adaptive layouts by breakpoint:
• Desktop: full analytical density with wide tables and multi-panel context.
• Tablet: condensed paneling with preserved action visibility.
• Mobile: prioritized task flows with stacked content and simplified navigation.
Responsive behavior is guided by task criticality. Essential actions (start scan, view status,
inspect critical findings) remain reachable at all sizes.
### 5.7.3 Mobile and Tablet Considerations
Smaller screens prioritize:
• Critical scan state information.
• Severity-first finding summaries.
• Minimal-form workflows for target submission.
• Access to AI guidance and report actions.
### 5.7.4 UX Risk Controls
Potential UX failure modes include overloaded result pages, ambiguous errors, and hidden
critical actions. The design addresses these through progressive disclosure, explicit error
messaging, and action placement consistency.
## 5.8 Chapter Summary
This chapter presented UI/UX design as a core operational subsystem of SafeWeb-AI. It
defined usability goals, principle-driven design choices, information architecture, user
journeys, major interface groups, visual system logic, and accessibility/responsiveness
strategy. The overall design objective is to make high-complexity cybersecurity workflows
understandable and actionable without sacrificing security context.
Chapter 6 transitions from design rationale to frontend implementation details, covering
how these UX decisions are realized in React-based architecture, route structure, API
integration, and state management behavior.
# Chapter 6: Frontend Implementation
This chapter references frontend engineering standards, React and Vite implementation
guidance, API integration patterns, and token-based web authentication considerations in
the context of SafeWeb-AI [15], [19], [20], [21], [55], [61].

Chapter 6 uses Figure 6.1 and Table 6.1 to Table 6.2 as primary implementation navigation
references.
## 6.1 Frontend Technology Stack
SafeWeb-AI frontend is implemented as a React 18 single-page application using
TypeScript and Vite. This stack was selected to balance development speed,
maintainability, and runtime performance in a security-oriented interface that must handle
dense data, route-level complexity, and real-time state updates.
### 6.1.1 Why React
React is suitable for SafeWeb-AI because the platform requires component-level state
isolation, reusable UI primitives, and efficient rendering of frequently changing scan status
and findings. In vulnerability management interfaces, small UI inefficiencies can
significantly degrade analyst throughput. React’s declarative rendering and compositional
model support predictable updates when scan data streams in and filters change.
### 6.1.2 Why TypeScript
TypeScript strengthens interface reliability by enforcing typed contracts for API responses,
user context state, and component props. This is especially useful in cybersecurity systems
where incorrect severity mapping, malformed payload assumptions, or null-state
mishandling can produce misleading outputs.
### 6.1.3 Why Vite
Vite provides fast local development iteration and route-chunked production build output.
For a multi-page SPA with role-based sections, Vite’s build model reduces time-to-feedback
during development and supports manageable bundle segmentation for production
delivery.
### 6.1.4 Frontend Stack Summary
Layer Technology Role
View library React 18 Component-based UI
Language TypeScript Type safety and
maintainability
Build tooling Vite Fast dev cycle and optimized
production builds
Routing React Router DOM Public/protected/admin
route segmentation
HTTP client Axios API integration with
interceptors
Styling TailwindCSS Design-system-consistent
utility styling

## 6.2 Application Structure
The frontend codebase is organized by functional concerns to align with domain
workflows.
### 6.2.1 Structural Modules
1. Pages. Page components represent route-level surfaces such as login, dashboard,
scan creation, scan history, results, admin pages, and learning pages.
2. Components. Reusable UI components implement cards, badges, inputs, layout
wrappers, status blocks, and specialized scanner-centric widgets.
3. Context and hooks. Application-level concerns such as authentication state and real-
time data subscriptions are managed through context providers and custom hooks.
4. Services. API integration logic is centralized in a service module with endpoint
groups to preserve clear separation between UI concerns and transport concerns.
### 6.2.2 Route Architecture
The route map includes:
• Public routes: onboarding, authentication, informational pages, documentation,
policy pages.
• Auth-protected routes: dashboard, scan workflows, result pages, profile, scheduling,
scope and webhook management.
• Admin-only routes: admin dashboard, user and scan governance pages, operational
settings.
This structure mirrors backend authorization boundaries and improves mental model
consistency for users.
### 6.2.3 Lazy Loading and Error Boundaries
Route-level lazy loading reduces initial payload size while preserving feature richness.
Error boundaries per route improve containment by preventing localized rendering
failures from collapsing the entire application shell.
### 6.2.4 Module Responsibility Table
Frontend Module Responsibility
Routing layer Navigation, access control, fallback behavior
Auth context User session state and auth action dispatch
API service Endpoint wrappers, token handling,
interceptor logic
Scan pages Target submission, progress display, result
exploration
Admin pages Governance surfaces for operational control

Frontend Module Responsibility
Chat interface Contextual AI interaction and feedback
capture
## 6.3 Authentication Flow
Authentication behavior is implemented through a dedicated context provider and
centralized API helpers.
### 6.3.1 Auth Context Lifecycle
Auth context manages three core states:
1. Current user object.
2. Authentication status.
3. Loading status during session restoration.
On application mount, access token presence triggers profile verification call. Successful
verification restores session context; failure clears tokens and resets unauthenticated state.
### 6.3.2 Login and Registration Actions
Login and registration both receive token payloads from backend and store access/refresh
tokens through shared token helper functions. User profile data is then stored in context to
immediately unlock protected UI routes.
### 6.3.3 Logout and Session Invalidation
Logout behavior attempts refresh-token invalidation endpoint, then clears local token
storage regardless of response outcome. This fail-safe strategy prevents stale client-side
authentication state.
### 6.3.4 Token Refresh and Interceptor Queue
Axios response interceptor implements automatic refresh on 401 responses. To avoid
refresh storms under concurrent requests, the implementation uses:
• A single-flight refresh guard.
• A failed-request queue that is replayed after successful token renewal.
• Forced logout and redirect when refresh fails.
This approach improves session continuity while maintaining controlled failure behavior.
### 6.3.5 Protected Route Access
Protected routing is based on context-authenticated state and role checks for admin routes.
This enforces frontend navigation boundaries aligned with backend permission controls.

## 6.4 Scan Workflow UI
Scan workflow UI translates complex backend operations into a manageable interaction
sequence.
### 6.4.1 Target Intake and Validation
Scan form captures target and scan parameters (depth/scope and optional behavior flags).
Frontend validation improves data quality before transmission, while backend validation
remains authoritative.
### 6.4.2 Scan Submission
Submission triggers API call to scan creation endpoint. Response includes scan identifier
and initial state used to route user into progress monitoring flow.
### 6.4.3 Scope Resolution and Confirmation Flows
For wide-scope behavior, UI supports intermediate confirmation logic where discovered
domains can be reviewed and selected before execution proceeds. This prevents
uncontrolled expansion and supports user-governed scope boundaries.
### 6.4.4 Real-Time Progress Integration
Progress UI consumes stream events and status polling fallback to provide near-live
visibility into phase transitions, tool execution context, and completion/failure outcomes.
### 6.4.5 User Experience During Long-Running Tasks
Long-running scans are handled through explicit states and informative messaging. Users
can navigate without losing context, and scan history surfaces preserve continuity when
sessions are interrupted.
## 6.5 Results Rendering
Result rendering is designed for both rapid triage and deep investigation.
### 6.5.1 Finding Presentation Model
Findings are rendered with:
• Severity labels.
• Category and vulnerability naming.
• Affected endpoint context.
• Evidence excerpts.
• Verification and confidence-related indicators.

### 6.5.2 Filtering and Search
Results views support filtering by severity, category, and search terms. This reduces
analyst time spent manually scanning dense tables and supports targeted remediation
planning.
### 6.5.3 Comparison and Drill-Down
Detailed finding pages allow deeper inspection of evidence and remediation text.
Comparison endpoints support trend and delta analysis across scans.
### 6.5.4 Export Integration
Results interface includes report export controls with format selection logic. Frontend
handles binary and JSON-style responses according to selected format.
### 6.5.5 Severity Visualization Strategy
Severity-to-visual mapping is consistent across pages to avoid interpretation ambiguity.
Critical findings are intentionally prominent, while informational findings remain available
but less dominant.
## 6.6 AI Chat UI
AI chat UI is implemented as a first-class support channel rather than a detached demo
widget.
### 6.6.1 Interaction Model
Users can send free-form questions that include optional scan context identifiers. Backend
orchestrates assistant response with function-bound operations where applicable.
### 6.6.2 Session and Message Management
Chat API endpoints support session listing, session detail retrieval, and feedback capture
per assistant message. This enables both usability iteration and assistant governance.
### 6.6.3 Scan-Aware Prompting
Frontend can include scan context in request payload, allowing assistant responses to
reference recent scan status and findings.
### 6.6.4 AI UX Safety Considerations
The UI positions assistant output as guidance. Deterministic scan results remain the
canonical source of vulnerability truth.
## 6.7 Error Handling
Error handling in SafeWeb-AI frontend is designed for resilience and clarity.

### 6.7.1 Validation Errors
Client-side validation catches basic input issues early. Backend validation errors are
displayed in user-readable form without leaking sensitive internals.
### 6.7.2 Network and Authorization Errors
Transport failures and 401/403 responses are handled through interceptor logic and route
guards. Refresh failure path clears auth state and redirects to login.
### 6.7.3 Scan Failure States
If scan execution fails, UI exposes failure status and associated message where available.
This avoids silent failure and supports user recovery decisions.
### 6.7.4 Fallback and Recovery
Critical paths include fallbacks, such as queueing failed requests during token refresh and
retrying after successful renewal.
### 6.7.5 Error Strategy Matrix
Error Type Handling Strategy
Form validation error Inline field messaging
Authentication expiry Auto-refresh then replay
Refresh failure Token clear and login redirect
Network interruption Controlled rejection and user feedback
Scan execution failure Status surfacing and retry/rescan pathways
## 6.8 Performance and UX Considerations
### 6.8.1 Rendering Efficiency
Route-level lazy loading and targeted component rendering reduce initial load pressure
and improve perceived performance in large multi-page interface sets.
### 6.8.2 State Management Discipline
Auth state is centralized, while feature states remain local or service-driven. This reduces
global-state complexity and limits rerender cascades.
### 6.8.3 API Efficiency
Centralized API service wrappers reduce duplication and improve maintainability. Token
interception logic avoids repetitive auth boilerplate in page components.

### 6.8.4 Responsiveness Across Devices
UI layout strategy prioritizes core actions and risk indicators at smaller breakpoints. Dense
analytical views are preserved for desktop while mobile surfaces remain operationally
useful.
### 6.8.5 UX Performance Risks
Potential risks include heavy result rendering for large finding sets and event-stream burst
noise. Mitigation approaches include pagination, incremental rendering strategies, and
bounded update frequency where needed.
## 6.9 Chapter Summary
This chapter documented frontend implementation as an operational subsystem that
translates backend security workflows into usable analyst interactions. It covered stack
rationale, module organization, authentication and token lifecycle handling, scan workflow
rendering, finding exploration patterns, AI chat integration, error resilience, and
performance-minded UX behavior. The chapter demonstrates that SafeWeb-AI frontend is
designed as a robust security interface, not a presentation-only layer.
Chapter 7 continues this implementation narrative by detailing backend services, API
governance, orchestration control, and security enforcement.
# Chapter 7: Core Backend Implementation
Backend implementation analysis in this chapter is based on Django and DRF architecture
guidance, asynchronous processing patterns, secure token handling, and SafeWeb-AI
backend source documentation [14], [15], [16], [17], [18], [55], [60].
In the print-ready manuscript, this chapter references Figure 7.1 and Table 7.1 to Table 7.2
for architectural reading continuity.
## 7.1 Backend Stack
SafeWeb-AI backend is implemented with Django 5 and Django REST Framework (DRF),
combined with Celery for asynchronous execution and Redis for broker-backed task
dispatch. The backend is not only a data API; it is a policy and orchestration layer
responsible for secure request handling, lifecycle governance, and integration across
scanning subsystems.
### 7.1.1 Core Technology Roles
• Django: domain modeling, app modularization, ORM, security middleware.
• DRF: API views/serializers, permission layers, standardized response behavior.
• SimpleJWT: token-based authentication with refresh lifecycle support.

• Celery: distributed task execution for long-running scans.
• Redis: queue broker and task transport.
• PostgreSQL/SQLite (environment-dependent): persistent domain storage.
### 7.1.2 App-Level Modularity
Backend responsibilities are distributed across focused apps:
1. accounts: identity, session, API key, contact and application entities.
2. scanning: scan lifecycle, vulnerabilities, webhooks, scheduling, scope and asset
records.
3. chatbot: conversation sessions/messages and assistant orchestration.
4. ml: model interfaces and feature extraction utilities.
5. admin_panel: administrative settings and alert domain.
6. learn: educational content domain.
This modularity supports long-term maintainability by reducing cross-domain coupling.
## 7.2 API Layer
The API layer is organized by domain route prefixes and endpoint families.
### 7.2.1 Authentication Endpoints
Authentication API includes register, login, logout, verify, refresh, and password workflows.
Token-based behavior supports SPA usage patterns and route-level access controls.
### 7.2.2 Scan Management Endpoints
Scan domain endpoints support:
• Website scan creation.
• Scope resolution and confirmation workflows.
• Scan detail retrieval.
• Rescan and deletion.
• Findings retrieval and operations.
• Export flows.
• Stream endpoint access for live updates.
• Scope, webhook, scheduled scan, multi-target, and asset operations.
The breadth of endpoints reflects platform orientation rather than single-feature scanning.
### 7.2.3 Chat and AI Endpoints
Chat endpoints provide message submission, session retrieval, suggestion feeds, feedback,
and analytics hooks, enabling both user-facing utility and quality monitoring.

### 7.2.4 Admin Endpoints
Admin APIs support dashboard stats, user and scan governance, settings updates, and
operational datasets.
### 7.2.5 API Transport and Serialization
API responses are serialized via DRF serializers with structured validation. Camel-case
parser/renderer settings align payload style with frontend expectations while preserving
backend field integrity.
### 7.2.6 API Domain Table
API Domain Core Function
Auth Identity lifecycle and token management
User profile Profile updates, API keys, sessions, 2FA
operations
Scan Full scan lifecycle and findings operations
Dashboard Aggregated user-level metrics and trends
Chat Assistant interaction and conversation
persistence
Admin Governance and operational control
Learn Security education content delivery
## 7.3 Authentication and Authorization
Backend security depends on strict distinction between authentication (who is calling) and
authorization (what they can do).
### 7.3.1 Authentication Workflow
Authentication uses JWT bearer tokens with refresh flow. Access token is attached to
protected requests; refresh token supports session continuity and controlled renewal.
### 7.3.2 User Model and Identity Boundaries
Custom user model uses email-based authentication and includes role/plan metadata plus
optional two-factor-related fields. This enables identity governance and role-aware
behavior.
### 7.3.3 Permission Enforcement
DRF default permission is authenticated access, with explicit role checks on administrative
operations. Ownership constraints are used in querysets so users can only access their own
scan and profile data unless authorized otherwise.

### 7.3.4 Session and API Key Features
UserSession and APIKey models support account security and programmatic access
pathways. Usage metadata contributes to operational visibility and abuse tracing.
### 7.3.5 Auth Control Matrix
Control Backend Implementation Intention
Login/registration Dedicated auth views and serializers
JWT enforcement DRF JWT authentication class
Token refresh Auth refresh endpoint and lifecycle logic
Role checks Permission classes and role-aware views
Ownership checks Queryset filtering by authenticated user
2FA support Profile endpoints and model-level fields
## 7.4 Scan Orchestration
Scan orchestration is a primary backend responsibility connecting API intent to worker
execution.
### 7.4.1 Scan Creation Path
Website scan creation endpoint validates input, persists scan record, sets initial status
based on scope behavior, and dispatches execution task through Celery when applicable.
### 7.4.2 Dispatch Strategy
Dispatch helper attempts asynchronous task queueing. If broker or worker path is
unavailable in specific runtime modes, fallback behavior can invoke background threading
to avoid blocking request completion.
### 7.4.3 State Transition Management
Scan status transitions are persisted and updated as phases progress. Core states include
pending, scanning, completed, failed, and scope-confirmation related states for broader
target models.
### 7.4.4 Rescan Behavior
Rescan endpoint clones relevant configuration from an existing scan and dispatches a new
scan record. This preserves historical integrity and avoids mutating completed scan
artifacts.
### 7.4.5 Scope-Aware Orchestration
Wide-scope and wildcard-like behaviors include resolution/confirmation logic before full
scanning. This adds governance to attack-surface expansion and reduces accidental
overreach.

### 7.4.6 Progress Tracking and Streaming
Backend stores progress metadata and provides stream interfaces for real-time status
consumption. This supports frontend observability and user trust in long tasks.
## 7.5 Database Interaction
Backend persistence uses Django ORM with relationship-aware modeling and serializer-
driven input controls.
### 7.5.1 ORM Strategy
Core scan retrieval patterns use user-scoped querysets and related-entity prefetching for
efficient result retrieval. This improves list/detail view performance for finding-heavy
scans.
### 7.5.2 Write Path Strategy
Write operations prioritize:
1. Early validation.
2. Controlled create/update operations.
3. State consistency for lifecycle-critical entities.
4. Explicit update field scoping when possible.
### 7.5.3 JSON-Rich Fields and Flexibility
Recon and tester outputs require flexible structures. JSON-like fields are used where
schema variability is expected, while high-value relationships remain relational.
### 7.5.4 Audit-Relevant Persistence
Timestamp fields, status values, and ownership relationships support audit and historical
analysis requirements.
## 7.6 Validation and Error Management
Backend robustness depends on defensive validation and predictable failure behavior.
### 7.6.1 Input Validation
Serializers enforce data type and domain constraints before execution. This reduces
malformed task dispatch and downstream scan errors.
### 7.6.2 Exception Handling Behavior
Views are designed to return structured error responses with appropriate status codes
(e.g., 400 for validation issues, 404 for ownership/not-found cases). Internal exceptions are
logged with contextual metadata.

### 7.6.3 Graceful Failure in Orchestration
If task dispatch or scan phase execution fails, scan records are transitioned to failed state
with error message context. This ensures transparency and prevents silent loss of
execution state.
### 7.6.4 Logging Strategy
Application and framework logging are configured to capture operational diagnostics with
timestamp and module context. This is important for incident triage and debugging in
distributed execution contexts.
### 7.6.5 Validation/Error Matrix
Failure Class Handling Pattern
Bad input payload Serializer rejection with client error
response
Unauthorized access Auth/permission denial response
Missing resource Scoped 404 response
Dispatch failure Logged warning/error + controlled
fallback/state update
Execution exception Scan failure state with persisted error
message
## 7.7 Security Controls
Backend security controls are layered through middleware, auth classes, model ownership
checks, and operational settings.
### 7.7.1 Middleware and Security Headers
Django security middleware settings include content-type sniffing protection, frame
restrictions, and environment-aware secure cookie behavior.
### 7.7.2 CORS and CSRF Controls
CORS and CSRF trusted origins are explicitly configured to restrict cross-origin behavior
while supporting designated frontend deployments.
### 7.7.3 Throttling and Abuse Reduction
DRF throttle classes and rate settings provide baseline protection against abusive request
bursts.
### 7.7.4 Permission and Ownership Controls
Ownership-filtered querysets and explicit permission classes reduce horizontal privilege
abuse risk.

### 7.7.5 Sensitive Configuration Handling
Environment variables are used for runtime-sensitive configuration such as keys, broker
URLs, and API credentials. This supports safer deployment practices than hardcoded
secrets.
### 7.7.6 Security Boundary Table
Security Boundary Enforcement Mechanism
Request origin CORS and CSRF trusted policy
Identity JWT auth enforcement
Privilege Role-aware permission checks
Data ownership User-scoped querysets
Abuse control API throttling configuration
Secret exposure Environment-based settings management
## 7.8 Chapter Summary
This chapter documented backend implementation as the policy and orchestration core of
SafeWeb-AI. It covered technology stack rationale, API domain architecture,
authentication/authorization controls, scan dispatch and lifecycle management, ORM
interaction patterns, defensive validation and error handling, and layered backend security
controls. The chapter demonstrates that backend design prioritizes secure governance,
resilience, and modular expansion.
Chapter 8 extends this implementation discussion into the scanner engine internals, where
recon, testing, verification, and correlation logic are executed.
# Chapter 8: Scanning Engine Implementation
The scanning engine discussion in this chapter is aligned with OWASP testing guidance,
practical penetration-testing tool references, and SafeWeb-AI orchestration design
documentation [2], [30], [32], [33], [34], [35], [36], [37], [38], [39], [49], [60].
This chapter maps directly to Figure 8.1 through Figure 8.3 and Table 8.1 through Table 8.4
for scanner internals and scoring interpretation.
## 8.1 Scan Orchestrator
The scan orchestrator is the execution nucleus of SafeWeb-AI. It coordinates phase
progression, controls state transitions, manages integration boundaries, and ensures that
scan artifacts remain traceable from creation to completion. Architecturally, the
orchestrator functions as a pipeline controller, not as a monolithic tester.

### 8.1.1 Orchestration Responsibilities
1. Initialize scan execution context.
2. Update lifecycle status and progress metadata.
3. Execute phased modules in dependency-aware order.
4. Trigger asynchronous or parallel operations where safe.
5. Collect and normalize outputs for persistence.
6. Handle partial failures and continue where policy permits.
7. Finalize score and completion state.
### 8.1.2 Scope-Aware Execution
The orchestrator includes scope-specific behavior:
• Single-domain scans run full pipeline directly.
• Wider-scope configurations can trigger resolution and child-scan dispatch patterns.
This design avoids naive target expansion and preserves manageable execution
boundaries.
### 8.1.3 State and Progress Model
Scan records track progress percentage, current phase, and current tool context. This
model serves two purposes:
1. User-facing transparency through real-time updates.
2. Operational observability for troubleshooting and support.
## 8.2 Reconnaissance Engine
Reconnaissance is designed as staged intelligence acquisition, not a single probe pass. The
objective is to expand and enrich target context before heavy active testing begins.
### 8.2.1 Recon Objectives
• Discover reachable assets and related domains.
• Identify technology stack and infrastructure hints.
• Collect headers, cookie signals, and protocol metadata.
• Expand parameter and endpoint candidate sets.
• Produce intelligence inputs for prioritized testing.
### 8.2.2 Multi-Wave Recon Strategy
SafeWeb-AI recon follows wave-based progression.
Wave 0a: Independent probes. Examples include DNS and WHOIS intelligence, certificate
and baseline network signals.
Wave 0b: Response-dependent probes. Includes technology fingerprinting,
header/cookie/CORS analysis, and script-level reconnaissance.

Wave 0c: Cross-enrichment probes. Includes content and parameter discovery and broader
endpoint enrichment.
Wave 0d: Analytics and aggregation. Recon outputs are synthesized into attack-surface and
risk context.
### 8.2.3 Recon Design Benefits
• Better crawl targeting.
• Reduced blind testing overhead.
• Improved context for prioritization and verification stages.
### 8.2.4 Recon Risks and Controls
Recon can expand quickly on large targets. Controls include bounded scope policy, selective
module execution, and rate-awareness to reduce intrusive behavior.
## 8.3 Crawling Engine
The crawling subsystem transforms reconnaissance hints into an actionable endpoint
graph.
### 8.3.1 Crawling Goals
1. Enumerate reachable routes and resources.
2. Discover forms and input surfaces.
3. Capture parameters for vulnerability payload targeting.
4. Support modern frontend behavior where JavaScript rendering affects
discoverability.
### 8.3.2 Strategy Characteristics
Crawling combines traversal logic with dynamic rendering support. In practice, this
improves discovery on single-page applications and route structures not visible through
static HTML alone.
### 8.3.3 Form and Interaction Discovery
Form interaction support identifies candidate fields and submission paths for subsequent
tester modules. This directly improves coverage for injection and workflow-sensitive
vulnerability classes.
### 8.3.4 Crawl Output Usage
Crawler outputs feed:
• Tester target queues.
• Parameter fuzzing candidates.
• Attack-surface modeling context.

## 8.4 Analyzer Engine
Analyzer modules provide passive and semi-active security posture assessment before and
alongside active testing.
### 8.4.1 Header Analysis
Header analysis evaluates whether security-critical headers are present and appropriately
configured. It supports detection of misconfiguration classes and policy weaknesses.
### 8.4.2 TLS/SSL Analysis
TLS analyzer logic inspects certificate and transport security posture signals. This
contributes to deployment security evaluation and risk communication.
### 8.4.3 Cookie Analysis
Cookie analysis checks transport and scope-related attributes relevant to session security,
including secure and httpOnly usage patterns where applicable.
### 8.4.4 Analyzer Value
Analyzer findings often produce high-remediation-value outputs because many issues are
operationally fixable with lower engineering effort compared to deep code vulnerabilities.
## 8.5 Vulnerability Tester Framework
The tester framework is designed for extensibility and consistency across numerous
vulnerability classes.
### 8.5.1 Framework Architecture
Testers inherit common behavior from base abstractions and implement class-specific test
logic. Shared behavior generally includes:
• Target input preparation.
• Request execution patterns.
• Evidence extraction conventions.
• Finding object generation.
### 8.5.2 Category-Based Tester Organization
Tester categories span classic and modern classes, including:
• Injection families (SQLi, XSS, command injection, template injection).
• Access control and auth weaknesses.
• API and protocol-specific issues.
• Misconfiguration and exposure classes.
• Business logic and workflow-sensitive issues.

### 8.5.3 Prioritized Execution
The engine supports prioritized testing strategy informed by recon and contextual
intelligence, reducing random probing and improving useful signal density.
### 8.5.4 Extending the Tester Set
A new tester can be added by implementing the expected tester interface and registering it
through tester discovery/registry pathways. This modularity is essential for long-term
evolution of security coverage.
## 8.6 Tool Integration
External tool integration broadens capability beyond in-process testing modules.
### 8.6.1 Integration Purpose
Tool wrappers provide access to specialized ecosystems for:
• Subdomain discovery.
• Port and service reconnaissance.
• Fuzzing and content discovery.
• Signature/template vulnerability checks.
• Class-specific exploit probes.
### 8.6.2 Wrapper Normalization Layer
Wrapper architecture standardizes:
• Invocation patterns.
• Timeout and error handling behavior.
• Output transformation into orchestrator-consumable structures.
### 8.6.3 Error Tolerance and Graceful Degradation
Because external tools may be unavailable or misconfigured by environment, wrappers and
orchestrator are designed to degrade gracefully. A missing tool should reduce breadth, not
terminate entire scan lifecycle by default.
### 8.6.4 Tool Integration Governance
Tool usage remains under scope, rate, and phase controls. This prevents unmanaged
external command execution behavior.
## 8.7 Evidence Verification
Verification is a dedicated stage for confidence management.

### 8.7.1 Why Verification Matters
Raw detections are useful but not all detections are equally reliable. Explicit verification
reduces false positives and improves user trust in results.
### 8.7.2 Verification Operations
Verification logic can include:
• Re-testing with alternate payload or method.
• Differential response analysis.
• Confidence score adjustment.
• Evidence enrichment in final finding record.
### 8.7.3 Verification Outcomes
Each finding can carry verification metadata and confidence-related fields to support
analyst triage and risk prioritization.
## 8.8 Correlation and Attack Chains
Correlation is implemented to move from isolated findings toward risk narratives.
### 8.8.1 Correlation Objectives
1. Detect related findings affecting shared assets.
2. Identify compounding risk conditions.
3. Support attack-path reasoning for prioritization.
### 8.8.2 Attack Chaining Concept
Attack chains model scenarios where multiple medium-severity issues can combine into a
high-impact outcome. This perspective improves remediation prioritization compared with
severity-only sorting.
### 8.8.3 Correlation Constraints
Correlation should remain evidence-aware. Weakly supported chains should be presented
as hypotheses or low-confidence links rather than deterministic exploitation claims.
## 8.9 Risk Scoring
Risk scoring converts vulnerability distributions into a summarized security posture
indicator.
### 8.9.1 Scoring Model
SafeWeb-AI uses a bounded score model that starts from a maximum and applies severity-
based deductions. This produces an interpretable aggregate measure while preserving
detailed findings for actual remediation.

### 8.9.2 Deduction Logic
Documented deduction rules are:
• Critical: -25
• High: -15
• Medium: -8
• Low: -3
• Informational: -1
### 8.9.3 Scoring Interpretation
Score is not a replacement for human risk assessment. It is a compact prioritization aid that
helps teams communicate posture changes across scans.
### 8.9.4 Risk Scoring Table
Severity Deduction
Critical 25
High 15
Medium 8
Low 3
Info 1
## 8.10 Report Generation
Reporting translates scan artifacts into consumable outputs for operational and
governance workflows.
### 8.10.1 Reporting Objectives
1. Preserve finding details and evidence context.
2. Support machine-readable and human-readable consumption.
3. Enable export for audit, communication, and remediation tracking.
### 8.10.2 Output Format Architecture
Current user-facing export flow is explicitly exposed for common formats through scan
export endpoints and report entities. Documented and implemented paths center on
practical operational formats (for example structured JSON and presentation-friendly
documents).
For broader interoperability targets, format adapters can conceptually extend toward
standardized developer-security formats (such as SARIF) and rich web-rendered outputs
(HTML). Where such adapters are not explicitly exposed as first-class endpoints in the
current build, they should be treated as extensibility pathways rather than claimed default
outputs.

### 8.10.3 Report Content Structure
A mature report should include:
• Executive summary and target context.
• Vulnerability breakdown by severity/category.
• Evidence snippets and affected URLs.
• Risk score and prioritization cues.
• Remediation guidance references.
### 8.10.4 Report Storage and Retrieval
Report metadata is tracked in relational entities while generated artifact files are stored in
dedicated storage pathways.
## 8.11 Operational Safety
Operational safety is essential when building offensive-security-adjacent automation.
### 8.11.1 Scope Safety
Scan execution is constrained by target submission and scope configuration rules to reduce
misuse risk.
### 8.11.2 Rate and Resource Safety
Rate-aware mechanisms and bounded concurrency protect both scanner stability and
target-side tolerance.
### 8.11.3 Timeout and Failure Safety
Long-running tasks use timeout and failure-handling controls. Partial failures are captured
and surfaced rather than hidden.
### 8.11.4 Tool Execution Safety
Tool invocation through wrappers reduces uncontrolled command execution risk and
centralizes safety handling.
### 8.11.5 AI Safety Interaction
AI components are assistive and constrained; they do not bypass deterministic scanner
controls or directly authorize unsafe operations.
### 8.11.6 Safety Control Matrix
Safety Concern Control Strategy
Scope overreach Validation and confirmation workflows
Excessive request intensity Rate limiter and phased execution
Tool instability Wrapper isolation and graceful degradation

Safety Concern Control Strategy
Long-running overload Async workers and timeout controls
Misleading output confidence Verification and confidence fields
AI misuse Function-bounded actions and policy
constraints
## 8.12 Chapter Summary
This chapter presented the full scanning engine implementation strategy of SafeWeb-AI,
from orchestration through recon, crawling, analysis, testing, verification, correlation,
scoring, and reporting. It highlighted key architectural decisions such as phased execution,
wrapper-based tool normalization, confidence-aware finding processing, and operational
safety controls. The chapter demonstrates that the scanner is implemented as a structured
and governable pipeline rather than an uncoordinated set of scripts.
Chapter 9 expands on intelligent components by detailing AI and ML integration
boundaries, capabilities, and safety constraints.
## 8.10 Autonomous Multi-Agent StateGraph Architecture

The current SafeWeb-AI architecture introduces an explicit agent-orchestration layer in `langgraph_engine.py`. This layer models an engagement as a directed graph \(G=(V,E)\), in which the vertex set is

\[
V=\{\text{scope\_gate},\text{recon},\text{vuln\_scan},\text{exploit},\text{validator}\}
\]

and the implemented edge set is

\[
E=\{(\text{scope\_gate},\text{recon}),(\text{recon},\text{vuln\_scan}),
(\text{vuln\_scan},\text{exploit}),(\text{exploit},\text{validator}),
(\text{validator},\text{END})\}.
\]

The graph carries a typed shared state rather than relying on unstructured messages between agents. `ScanState` contains the scan identifier, target URL, authorization allowlist, current flow status, discovered endpoints, candidate vulnerabilities, verified vulnerabilities, accumulated execution cost, and engagement log. This state contract is significant because it makes hand-offs inspectable. Each specialist receives the state produced by its predecessor and returns a partial state update. The resulting execution history can therefore be persisted, streamed, tested, and reconstructed without relying on hidden conversational memory.

The StateGraph is a specialized coordination plane; it does not replace deterministic security modules. The reconnaissance node invokes registered tools such as Subfinder and HTTPX through the tool registry’s MCP-shaped interface. The vulnerability node transforms the discovered surface into candidate findings. The exploit specialist applies vulnerability-specific skill context and invokes bounded verification tools. The validator then subjects claimed findings to a deterministic re-proof policy before the result is admitted to the final verified set. In this design, language-model reasoning may propose a course of action, but only scoped tools can act, and only evidence-oriented code can establish vulnerability truth.

This separation addresses a central weakness of monolithic DAST loops. A procedural scanner commonly embeds discovery, probing, classification, and reporting in one long control path. Failure in one tool can terminate unrelated work, intermediate reasoning is difficult to inspect, and adding a new phase increases coupling. The graph makes the phase boundary explicit. It also provides a foundation for future conditional edges, retries, specialist fan-out, and policy-directed termination. The checked-in graph is presently linear, however, and should not be described as already implementing every possible reactive branch. Its architectural contribution is the typed graph boundary and specialist-node contract; more advanced conditional routing remains an extension point.

> **[FIGURE PLACEHOLDER: Figure 8.4 — SafeWeb-AI LangGraph Specialist Pipeline]**
> *Visual Specification:* Draw five rounded nodes from left to right: `ScopeGate`, `Recon Specialist`, `Vulnerability Scanner`, `Exploit Specialist`, and `PoC Validator`. Place a `ScanState` data band beneath the nodes and show each node reading from and writing to that band. Add the labels `scope_allowlist`, `discovered_endpoints`, `candidate_vulnerabilities`, `verified_vulnerabilities`, `current_cost`, and `engagement_log` inside the band. Show the validator connecting to `END / persisted result`, and use a dashed feedback arrow labeled `future conditional retry` to distinguish designed extensibility from the currently linear edge set.

### 8.10.1 Coordinator and Sandbox Boundaries

SafeWeb-AI separates management intent from offensive execution. The Django and Celery layers form the coordination plane: they authenticate users, associate operations with organization scope, persist scan state, dispatch asynchronous work, and expose progress through REST and SSE interfaces. The execution plane consists of the internal tester framework, external tool wrappers, asynchronous task runners, headless browser automation, and the dedicated `agent_sandbox` container described by the local compose topology.

This boundary has both reliability and ethical value. Tool processes are more failure-prone than ordinary application requests because they depend on network behavior, subprocess availability, target responsiveness, and potentially malformed output. Running them behind a normalized wrapper contract prevents raw tool behavior from leaking into the API layer. The `ExternalTool` abstraction and `ToolRegistry` provide availability checks, capability metadata, timeout handling, and graceful degradation. The repository contains 61 wrapper modules registered by `register_all_tools()`. Registration does not imply that every corresponding binary is installed in every runtime; the health endpoint and registry availability checks are therefore part of the operational truth of the platform.

The compose topology further defines an `agent_sandbox` service reachable by the Celery worker over an isolated bridge network. The sandbox boundary is a valuable defense-in-depth mechanism, but container separation alone is not a complete security proof. Production hardening also requires a non-root runtime, a read-only filesystem where practical, dropped Linux capabilities, egress allowlisting, CPU and memory quotas, process-count limits, and per-engagement credentials. These controls constrain the blast radius of a malformed target, compromised third-party tool, or hostile response processed by an AI-assisted component.

### 8.10.2 Scope Gate and Authorization Invariants

Authorization is the primary safety invariant of an offensive security platform. Let \(T\) be the normalized target origin and \(A=\{a_1,\ldots,a_n\}\) the authorized set of exact hosts, domain suffixes, CIDR ranges, and explicit exclusions. Execution is permitted only when

\[
\operatorname{Permit}(T,A)=
\operatorname{Normalized}(T)\land
\operatorname{InAllowlist}(T,A)\land
\neg\operatorname{Excluded}(T,A)\land
\neg\operatorname{ForbiddenAddress}(T).
\]

`ForbiddenAddress` must reject loopback, link-local, multicast, unspecified, and private-address destinations unless an engagement explicitly authorizes the relevant range. DNS must be resolved and rechecked at connection time to reduce DNS-rebinding and time-of-check/time-of-use risk. Redirect destinations and newly discovered subdomains must pass the same predicate; authorization cannot be inherited merely because an in-scope page linked to a new host.

The current `langgraph_engine.py` scope-gate function records an approved log entry and advances the graph without evaluating the supplied allowlist. This is a verified implementation gap, not evidence that scope control is absent from the wider platform: separate scope-resolution and scope-management modules and API workflows exist. Nevertheless, the graph-level invariant should be enforced before the StateGraph becomes an independent production execution path. The academically defensible conclusion is that the architecture specifies defense in depth, while the current graph adapter requires integration with the authoritative scope resolver.

## 8.11 Eight-Phase Execution Semantics

The five-node graph is the high-level reasoning topology, whereas the scanner engine exposes a more granular operational pipeline. These views are complementary. The graph answers which specialist owns a decision; the phase model answers which technical activities occur and in what order.

### 8.11.1 Phase 0: Pre-Flight and Scope Establishment

Pre-flight processing normalizes the URL, resolves DNS, evaluates reachability, validates authorization boundaries, initializes request budgets, and fingerprints defensive infrastructure. Passive WAF observations inform later rate and payload choices but do not authorize evasion by themselves. A scan that fails scope validation must transition to a terminal refusal state, retain a minimal audit record, and execute no active probe.

### 8.11.2 Phase 0.5: Stateful Authentication

The authentication subsystem supports conventional session establishment and browser-mediated SPA flows. `HeadlessAuthFlow.run_auto_login()` creates a Playwright Chromium context, navigates to the login page, discovers likely username, password, and submit controls, submits credentials, waits for network stabilization, and captures cookies plus local and session storage. `_extract_auth_headers()` searches storage keys associated with access, JWT, token, or authorization state and transfers the selected value into an `Authorization: Bearer` header. `apply_to_session()` then injects cookies and headers into the HTTP client used by deterministic testers.

This bridge is important because browser state and scanner state are otherwise isolated. It allows authenticated API requests discovered after JavaScript execution to be replayed by lower-cost HTTP clients. The method remains heuristic: selector detection can fail, multi-factor challenges may require operator interaction, and storage keys do not guarantee that a long value is a valid JWT. Token parsing and cryptographic checks must therefore follow extraction rather than being inferred from the key name.

```python
# Listing 8.1 — Repository implementation of standalone SPA login
def run_auto_login(self, login_url: str, username: str = "",
                   password: str = "") -> HeadlessAuthResult:
    result = HeadlessAuthResult()
    if not HAS_PLAYWRIGHT:
        result.error = "Playwright not available"
        return result
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            context = browser.new_context()
            result = self.login_form(
                context, login_url, username, password
            )
            browser.close()
    except Exception as exc:
        result.error = str(exc)
    return result
```

### 8.11.3 Phase 1: Reconnaissance and Surface Expansion

Reconnaissance combines passive intelligence, DNS and certificate observations, subdomain enumeration, port and service discovery, HTTP probing, dynamic crawling, JavaScript analysis, parameter discovery, and screenshot evidence. The internal recon package contains specialized modules rather than a single universal crawler. This decomposition allows each evidence source to be normalized and assigned provenance.

For a discovered artifact \(x\), the normalized record should contain at least \((u,s,t,\tau,m)\): canonical URL \(u\), source \(s\), status \(t\), observation time \(\tau\), and metadata \(m\). Provenance is essential because an archived URL, a live HTTP probe, and a JavaScript string literal carry different confidence. Deduplication should merge equivalent origins and paths without erasing those distinctions.

### 8.11.4 Phases 2–4: Candidate Discovery

Candidate discovery executes internal testers and external wrappers according to profile, depth, technology evidence, and authorization. The repository audit identifies 87 concrete modules that declare a `BaseTester` subclass. The number represents concrete source modules at rewrite time, not a claim that all testers have equal maturity or execute for every profile. Profile selection and preconditions prevent the full set from becoming an indiscriminate request storm.

The wrapper ecosystem contains 61 registered integrations spanning reconnaissance, crawling, parameter mining, network mapping, template scanning, injection testing, CMS analysis, secret discovery, cloud enumeration, screenshots, and out-of-band interaction. Outputs are normalized into the platform finding model. Missing binaries, non-zero exit status, malformed output, and timeout are treated as tool-state observations rather than automatically as target findings.

### 8.11.5 Phase 5: Deterministic Verification

`VerificationEngine.verify_all()` selects high and critical candidates and schedules independent confirmation through `AsyncTaskRunner(max_concurrency=20, default_timeout=20.0)`. The concurrency bound prevents an unbounded candidate list from consuming all sockets or worker threads. Each vulnerability class uses a secondary technique: XSS receives a unique reflection canary, SQL injection uses timing differentiation, SSTI uses an alternative arithmetic expression, redirect findings inspect the `Location` header, and unsupported categories fall back to response comparison.

```python
# Listing 8.2 — Concurrency-bounded verification dispatch
async def verify_all(self, vulns: list,
                     depth: str = "medium") -> list[VerificationResult]:
    runner = AsyncTaskRunner(max_concurrency=20, default_timeout=20.0)
    for vuln in vulns:
        if vuln.get("severity", "info") not in ("critical", "high"):
            continue
        runner.add(vuln.get("_id", ""), self._verify_single, args=(vuln,))
    task_results = await runner.run()
    return [
        result.result if result.result else VerificationResult(
            vuln_id=key,
            confirmed=False,
            confidence=0.3,
            confirmation_method="error",
            evidence=f"Verification error/timeout: {result.error}",
        )
        for key, result in task_results.items()
    ]
```

For verification result \(i\), the implementation defines the false-positive score as

\[
FP_i=\operatorname{round}(1-C_i,3),\qquad 0\leq C_i\leq 1,
\]

where \(C_i\) is the confidence assigned by the independent check. A filtering rule \(FP_i>0.7\) therefore corresponds to confidence below \(0.3\). Severity and confidence must remain distinct dimensions: severity estimates impact if true, while confidence estimates evidentiary support.

### 8.11.6 Phase 5.7: Safe Proof Generation

The exploit-generation layer converts confirmed evidence into reproducible, non-destructive artifacts. A proof capsule should contain the precise target, method, relevant headers, sanitized request body, bounded payload, response indicator, timestamp, and tool provenance. Reproduction commands must remove secrets and avoid destructive mutations. The objective is not to maximize exploit impact but to demonstrate the smallest repeatable condition needed for remediation and peer review.

### 8.11.7 Phase 6: Report Synthesis

Reporting maps normalized findings to CWE, OWASP, and CVSS metadata and produces human-readable remediation guidance. CVSS v3.1 base scoring is computed from exploitability and impact:

\[
Exploitability=8.22(AV)(AC)(PR)(UI),
\]

\[
ISC_{Base}=1-(1-C)(1-I)(1-A),
\]

with the scope-dependent impact equations and a final score rounded upward to one decimal place and capped at 10.0. The vector and metric values must be stored alongside the score so that a reviewer can reproduce the result.

### 8.11.8 Phase 7: Cross-Scan Memory

`ScanMemory` persists recent outcomes, technology-to-vulnerability observations, WAF bypass aggregates, and successful payload frequencies in `scan_memory.json`. `ScanOutcome` includes target, technology stack, WAF, finding counts, confirmed true and false positives, vulnerability types, best payloads, duration, vulnerability category, vulnerable outcome, payload used, and WAF presence/bypass flags.

The current implementation keeps the most recent 100 serialized outcomes and defaults to a neutral likelihood of 0.5 when evidence is absent. This restraint is appropriate because frequency is not causation and small sample sizes should not become deterministic policy. A verified defect remains: `record_outcome()` references `outcome.blocked_payloads`, which is not declared on the dataclass. Until corrected and covered by a persistence test, WAF aggregation on that path cannot be claimed as operational. Database-backed vector memory exists elsewhere in the repository, but the JSON `ScanMemory` class itself should not be misrepresented as PostgreSQL persistence.

## 8.12 Implementation Inventory and Interpretive Limits

Table 8.5 records the code-derived inventory used by this thesis. Counts are reproducible properties of the reviewed checkout and may change as modules are added or removed.

| Inventory item | Verified count | Counting rule |
| --- | ---: | --- |
| Django applications | 6 | Directories under `backend/apps` containing `apps.py` |
| ORM model classes | 32 | Classes deriving from `models.Model` or `AbstractUser` in application `models.py` files |
| Active application route patterns | 88 | Un-commented `path()` declarations in application URL modules |
| Concrete internal tester modules | 87 | Files declaring a `BaseTester` subclass, excluding package and base modules |
| Registered external wrapper modules | 61 | Modules imported and enumerated by `register_all_tools()` |
| LangGraph specialist nodes | 5 | Calls to `StateGraph.add_node()` in `langgraph_engine.py` |

These figures measure structural breadth, not validated detection efficacy. A large tester count can coexist with uneven test depth, and a wrapper can be registered while its binary is unavailable. The reliability claims in this thesis therefore rest on contracts, tests, evidence normalization, and explicit limitations rather than module quantity.

# Chapter 9: AI / Machine Learning System
This chapter draws on machine learning and LLM integration references, prompt-safety
guidance, and SafeWeb-AI AI subsystem documentation for bounded cybersecurity
assistance [40], [41], [42], [43], [44], [47], [60].
Chapter 9 references Figure 9.1 and Table 9.1 to Table 9.2 in the final formatted thesis.
## 9.1 AI Objectives
AI in SafeWeb-AI is implemented as an assistive layer to improve interpretation, workflow
efficiency, and prioritization quality. The design intentionally avoids treating AI as an
autonomous vulnerability oracle.
### 9.1.1 Core AI Objectives
1. Provide contextual explanation of scan outputs.
2. Assist users in navigating scan workflows and status retrieval.
3. Improve actionability of findings through remediation-oriented guidance.
4. Support confidence handling and triage assistance in combination with
deterministic evidence.
### 9.1.2 What AI Does Not Do
1. It does not replace deterministic test logic for vulnerability detection.
2. It does not guarantee exploitability conclusions without evidence.
3. It does not bypass authorization or execute unrestricted system actions.

## 9.2 LLM Integration
SafeWeb-AI chatbot integrates a large language model through an API-based inference path
and function-call action layer.
### 9.2.1 Integration Architecture
The chatbot engine mediates between user messages, model prompts, and action handlers.
Model output can either be direct response text or structured action intent requiring
backend function invocation.
### 9.2.2 Function-Calling Capability
The assistant is equipped with a bounded set of callable actions (for example start scan,
scan status retrieval, export guidance, and navigation-oriented assistance). This design
provides practical utility while preserving control boundaries.
### 9.2.3 Model Selection Strategy
Model usage prioritizes responsiveness and practical conversational quality suitable for in-
product support. The architecture remains provider-abstracted enough to permit model
replacement based on policy, cost, or quality requirements.
### 9.2.4 Fallback Considerations
Documented architecture includes local knowledge fallback behavior to preserve baseline
utility when remote model behavior is unavailable or constrained.
## 9.3 Prompt Engineering
Prompt design in cybersecurity contexts must balance helpfulness, safety, and scope
discipline.
### 9.3.1 Prompt Structure Goals
1. Provide domain context about SafeWeb-AI capability boundaries.
2. Ensure responses remain aligned with user intent and available scan data.
3. Prevent unsafe escalation into out-of-scope or unrestricted offensive instructions.
4. Standardize assistant tone toward actionable, evidence-aware guidance.
### 9.3.2 Instruction Layers
Prompt composition typically includes:
• System-level behavioral policy.
• Domain context injection.
• Tool/action capability declaration.
• Conversation history and current user query.

### 9.3.3 Prompt Reliability Practices
Reliable prompting in this system depends on deterministic scaffolding and explicit refusal
boundaries for unsafe requests.
## 9.4 Context Awareness
Context awareness is essential for assistant utility in scan-centric workflows.
### 9.4.1 Context Inputs
Assistant context can include:
• Recent scans.
• Current scan status.
• Vulnerability details.
• User profile and plan-level metadata where applicable.
• Conversation history constraints.
### 9.4.2 Context Injection Benefits
Context-aware responses reduce generic advice and improve relevance. Users receive
workflow-specific guidance rather than static textbook responses.
### 9.4.3 Context Boundaries
Context injection should remain minimal and purpose-driven to reduce leakage risk and
avoid unnecessary token overhead.
## 9.5 False Positive Reduction
False positive reduction in SafeWeb-AI is a hybrid process where AI and ML can contribute
but deterministic verification remains central.
### 9.5.1 Multi-Component Reduction Logic
Confidence handling combines signals from:
1. Verification pass outcomes.
2. Heuristic consistency checks.
3. Historical or contextual indicators.
4. Optional ML classification signals.
5. AI-assisted interpretation.
### 9.5.2 AI Role in Triage
AI can help summarize why a finding may require immediate attention or additional
verification, but final truth assignment should remain tied to evidence and verifier outputs.

### 9.5.3 Output Semantics
The system should clearly separate verified findings, suspected findings, and low-
confidence findings to preserve analyst trust.
## 9.6 Safe AI Usage in Cybersecurity
AI safety is not optional in a cybersecurity assistant. The platform applies layered
guardrails to reduce misuse and hallucination risk.
### 9.6.1 Guardrail Principles
1. Tool-bounded execution.
2. Scope-aware refusal behavior for unsafe prompts.
3. Context sanitization where untrusted input may contain prompt-injection patterns.
4. Non-authoritative framing for speculative content.
### 9.6.2 Prompt Injection Concerns
Scan data may include adversarial payloads or crafted strings designed to influence model
behavior. A robust system treats scan content as untrusted input and avoids blindly
elevating it into instruction-level context.
### 9.6.3 Safety-Aware Response Policy
Assistant responses should:
• Prefer defensive guidance.
• Avoid facilitating unauthorized offensive behavior.
• Redirect users toward legitimate remediation and governance actions.
### 9.6.4 AI Risk Table
AI Risk Mitigation
Hallucinated technical claim Evidence-first response framing
Prompt injection influence Input sanitization and context isolation
Unsafe exploitation guidance Refusal/constraint policy
Over-trust by users Explicit assistive-role communication
## 9.7 Training / Model Usage
This section distinguishes model usage roles based on available project artifacts.
### 9.7.1 LLM Usage Mode
The chatbot is implemented as an inference-time assistant integrated through model API
access and action tools. It is not documented as a custom fine-tuned LLM in the current
platform scope.

### 9.7.2 ML Components in Repository Scope
Project artifacts include ML modules such as:
• A phishing detector using gradient boosting with engineered URL features.
• A malware detector module with feature-based classification logic.
• Additional risk and false-positive reduction support components.
### 9.7.3 Scope Clarification
File and URL scan modes are documented as deactivated in the active web-pentest-focused
platform path. Therefore, ML component documentation in this thesis distinguishes
preserved model assets from currently active web-scan runtime pathways.
### 9.7.4 Model Governance Considerations
Even when models are inference-only or partially deactivated, engineering governance
should track:
• Feature assumptions.
• Training data provenance where available.
• Drift and validity boundaries.
• Operational activation policy.
## 9.8 AI/ML Architecture Summary Table
Component Role Operational Status
LLM Assistant Contextual chat guidance
and function-bound actions
Active
Chat Action Layer Bounded tool invocation Active
Local knowledge fallback Resilience for assistant
utility
Documented/available
pathway
Phishing detector Feature-based classification
module
Preserved component
Malware detector Feature-based classification
module
Preserved component
FP reduction ensemble Confidence refinement
support
Active in scan-confidence
pipeline
## 9.9 Chapter Summary
This chapter explained AI and ML integration in SafeWeb-AI as a disciplined assistive
subsystem rather than a replacement for deterministic scanner logic. It covered AI
objectives, LLM integration patterns, prompt engineering strategy, context injection, false-
positive triage contribution, guardrail design, and model usage boundaries. The chapter
establishes a safety-first, evidence-aware approach to AI in practical cybersecurity
operations.

Chapter 10 continues the system-level narrative by describing cloud infrastructure and
DevOps implementation for deployment, scaling, and operational governance.
# Chapter 10: Cloud Infrastructure and DevOps
Cloud and DevOps analysis in this chapter references Azure architecture and service
guidance, CI/CD operational documentation, and cybersecurity governance frameworks
mapped to the SafeWeb-AI deployment model [22], [23], [24], [25], [26], [27], [28], [29],
[46], [60].
Deployment interpretation in this chapter is tied to Figure 10.1 and Table 10.1 through
Table 10.2 in the print-ready version.
## 10.1 Deployment Architecture
SafeWeb-AI is documented as a cloud-native deployment architecture designed to support
reliable web security operations with separated runtime concerns, managed stateful
services, and production observability.
### 10.1.1 Deployment Topology
The deployment topology includes:
1. Frontend hosting for the React SPA.
2. Backend application hosting for Django REST services.
3. Managed relational database service.
4. Managed cache/broker service for asynchronous tasking.
5. Object storage for report and artifact retention.
6. Monitoring stack for telemetry, traces, and diagnostics.
7. Secret management service for runtime configuration security.
### 10.1.2 Service Separation Rationale
Security scanning workloads are heterogeneous. API responsiveness and scan execution
throughput should scale independently. The deployment architecture therefore separates:
• Interactive API path.
• Worker execution path.
• Data and artifact services.
This separation reduces cross-impact during spikes and failure scenarios.

### 10.1.3 Environment Segmentation
Environment segmentation supports safer operations across development, staging, and
production contexts. Each environment can apply controlled configuration and validation
gates prior to promotion.
## 10.2 Containerization
Containerization enables reproducible runtime behavior and dependency isolation.
### 10.2.1 Backend Runtime Container
Backend service container encapsulates Django runtime dependencies, API logic, and
configuration hooks.
### 10.2.2 Worker Runtime Container
Worker container isolates long-running scan execution and external tool orchestration
from user-facing API process concerns.
### 10.2.3 Security Tool Runtime Considerations
External security tooling often has heavy binary dependencies. Containerized sidecar or
dedicated execution images improve reproducibility and reduce host-level drift.
### 10.2.4 Data Service Boundaries
Stateful services (database, cache, object storage) are managed outside stateless app
containers to improve durability and operational consistency.
### 10.2.5 Containerization Trade-Offs
Container Role Benefit Trade-Off
API container Reproducible service
behavior
Requires robust
secret/config management
Worker container Isolated heavy execution Operational scaling
complexity
Tool execution images Dependency stability Image maintenance
overhead
## 10.3 CI/CD Strategy
Continuous integration and deployment strategy is critical for maintaining quality and
reducing release risk.
### 10.3.1 Pipeline Objectives
1. Validate code quality before release.
2. Build reproducible deployable artifacts.
3. Promote safely across environments.

4. Reduce downtime through controlled rollout mechanisms.
### 10.3.2 Typical Pipeline Stages
1. Source checkout and dependency setup.
2. Static checks and linting.
3. Automated tests.
4. Build and packaging.
5. Deployment to staging.
6. Smoke validation.
7. Production promotion.
### 10.3.3 Blue/Green and Slot-Based Concepts
Production-safe deployment can use staged slot swap patterns to minimize downtime and
simplify rollback logic when post-deploy checks fail.
### 10.3.4 Configuration Governance
Environment variables and secret references are kept externalized from code. This
supports safer credential handling and environment portability.
## 10.4 Scalability Strategy
Scalability in SafeWeb-AI centers on decoupled queue-driven execution.
### 10.4.1 API vs Worker Scaling
API scaling addresses concurrent user interactions, while worker scaling addresses scan
throughput. Independent scaling avoids over-provisioning one tier to compensate for the
other.
### 10.4.2 Queue-Driven Elasticity
Queue depth is a key operational signal for adding worker capacity. This allows gradual
scale-out under heavy scan demand.
### 10.4.3 Concurrency Controls
Concurrency must be bounded to avoid self-induced instability and target overloading. Safe
execution includes rate-awareness and task-level controls.
### 10.4.4 Scalability Risks
• Over-aggressive scaling without cost control.
• Bottlenecks at shared services.
• Tool binary contention in constrained environments.
Mitigation includes capacity planning, service telemetry, and staged scaling policies.

## 10.5 Storage and Data Services
### 10.5.1 Relational Persistence Service
The relational database stores identities, scans, vulnerabilities, scheduling metadata, and
conversational traces. It is optimized for integrity and queryability.
### 10.5.2 Cache and Broker Service
Cache/broker layer supports asynchronous task transport and can also contribute to
runtime acceleration for selected repeated reads.
### 10.5.3 Object Storage Service
Object storage holds generated report artifacts and large evidence outputs, preventing
primary database bloat and supporting archival workflows.
### 10.5.4 Data Lifecycle Perspective
Data lifecycle strategy should include:
1. Hot operational data for active scans.
2. Historical scan retention for trend analysis.
3. Archive or tiering policies for old artifacts.
### 10.5.5 Data Service Mapping
Data Service Data Type Primary Function
PostgreSQL Structured domain records Transactional integrity and
analytics queries
Redis Task and cache state Queueing and low-latency
coordination
Blob/Object storage Report/evidence artifacts Durable export and archival
support
## 10.6 Observability
Observability enables proactive operations and efficient incident response.
### 10.6.1 Observability Pillars
1. Logs for event-level diagnostics.
2. Metrics for system health and throughput.
3. Traces for request/task flow across components.
### 10.6.2 Operationally Relevant Metrics
Examples of high-value telemetry include:
• API response latency distributions.

• Queue depth and worker throughput.
• Scan completion and failure ratios.
• Dependency health signals.
### 10.6.3 Alerting and Incident Response
Alerting should be tied to service-level objectives and threshold breaches, including
sustained high error rates, queue saturation, and abnormal scan failure patterns.
### 10.6.4 Dashboarding
Operational dashboards should present both business and technical views: active scans,
severity trends, system load, and service health status.
## 10.7 Security Hardening
Cloud security posture extends beyond application logic and must include infrastructure
controls.
### 10.7.1 Secret Management
Sensitive values (keys, connection strings, tokens) should be stored in dedicated secret-
management systems and injected at runtime.
### 10.7.2 Identity and Access Boundaries
Principle of least privilege should guide service identity permissions, management-plane
access, and runtime resource access.
### 10.7.3 Network Segmentation and Exposure Control
Where feasible, private networking and controlled ingress reduce unnecessary exposure of
stateful services.
### 10.7.4 Transport and Storage Security
TLS enforcement for service communication and encryption-at-rest for managed storage
services are baseline requirements.
### 10.7.5 Hardening Checklist
Hardening Domain Control
Secrets Externalized vault-backed management
Access Least privilege and role separation
Network Reduced public exposure and controlled
ingress
Data Encryption in transit and at rest
Runtime Patch management and image hygiene
Monitoring Security-focused alerting and log review

## 10.8 Chapter Summary
This chapter documented the cloud and DevOps architecture of SafeWeb-AI from
deployment topology through containerization, CI/CD strategy, scalability model, data
services, observability, and security hardening controls. The core architectural theme is
operational separation: API interactivity, scan execution, and data durability are decoupled
to support resilience, scale, and governance. This deployment perspective completes the
implementation narrative and prepares the thesis for formal testing and evaluation
analysis.
Chapter 11 presents testing strategy and evaluation methodology across functional
correctness, security reliability, and performance behavior.
# Chapter 11: Testing and Evaluation
Testing and evaluation criteria in this chapter are informed by OWASP verification
guidance, secure software control references, and project-specific testing artifacts and
implementation evidence [2], [6], [45], [46], [60].
The chapter references Table 11.1 and Table 11.2 for formal test coverage and reliability
mapping.
## 11.1 Testing Strategy
Testing strategy in SafeWeb-AI is multi-layered because the platform combines interactive
frontend behavior, secure API workflows, asynchronous execution, scanner logic, and
external dependency orchestration. A single testing style is insufficient to validate such a
system.
The strategy is organized around five complementary layers:
1. Unit-level validation.
2. Integration-level validation.
3. Security-control validation.
4. Functional requirement validation.
5. Reliability and performance evaluation.
### 11.1.1 Test Design Principles
1. Risk-prioritized coverage: prioritize authentication, scan lifecycle, and finding
integrity paths.
2. Deterministic baseline first: validate core logic independent of external tool
variability.
3. Incremental confidence: combine fast checks with deeper end-to-end scenarios.

4. Observability-assisted diagnostics: use logs and state records for failure
interpretation.
### 11.1.2 Evaluation Scope
Evaluation in this thesis emphasizes:
• Correctness of major workflows.
• Robustness under dependency and runtime variability.
• Usability of outputs for security decision-making.
No unsupported benchmark claims are introduced; discussion is grounded in architecture
behavior and available test artifacts.
## 11.2 Unit Testing
Unit testing targets isolated logic where deterministic outcomes can be asserted.
### 11.2.1 Backend Unit Test Domains
1. Serializer and validation logic.
2. Utility functions (token/session helpers, score computation helpers).
3. Model behavior and constrained field logic.
4. Action handlers in chatbot and orchestration-support modules where deterministic.
### 11.2.2 Frontend Unit Test Domains
Where test harnesses are available, frontend unit focus includes:
1. Component rendering under state variants.
2. Form validation behavior.
3. Utility and formatter logic for severity/status display.
### 11.2.3 Unit Testing Benefits
Unit tests reduce regression risk for frequently changed code paths and provide early
warning for contract drift between modules.
## 11.3 Integration Testing
Integration testing is critical in SafeWeb-AI because subsystem boundaries are numerous.
### 11.3.1 API Integration Testing
API integration validates request/response contracts across key endpoint families:
• Authentication flows.
• Scan creation/detail/export flows.
• Chat session/message flows.
• Admin and dashboard access boundaries.

### 11.3.2 Queue and Worker Integration Testing
These tests verify that scan requests dispatched by API are correctly consumed by workers
and reflected in persisted status transitions.
### 11.3.3 Scanner Pipeline Integration Testing
Pipeline integration tests validate that:
1. Recon outputs feed crawling and testing phases.
2. Findings are persisted with expected structure.
3. Verification and scoring updates are reflected in final scan state.
### 11.3.4 External Tool Integration Testing
Because tool availability can vary by environment, integration tests evaluate both:
• Positive path (tool present and callable).
• Degraded path (tool unavailable, orchestrator continues safely).
### 11.3.5 Integration Coverage Matrix
Integration Surface Validation Focus
Frontend <-> API Contract consistency and auth behavior
API <-> Queue Dispatch reliability and task handoff
Queue <-> Worker Execution initiation and lifecycle updates
Worker <-> DB State persistence and artifact integrity
Worker <-> Tools Wrapper invocation and graceful
degradation
API <-> AI Chat action routing and response continuity
## 11.4 Security Testing
Security testing ensures that the platform itself remains defensible while performing
security assessment tasks.
### 11.4.1 Authentication and Authorization Security Tests
Core checks include:
• Protected endpoint access without token.
• Role-restricted admin route enforcement.
• Ownership constraints on scan and user resources.
• Session/token lifecycle correctness.
### 11.4.2 Input Validation and Injection Resistance
Security testing verifies that user-provided fields are validated and processed safely,
including target input and API payload boundaries.

### 11.4.3 Scan Safety Behavior
Scan safety tests evaluate whether scope controls, rate behavior, and failure boundaries
prevent uncontrolled execution patterns.
### 11.4.4 Output and Data Exposure Checks
Testing includes verifying that error responses and serialized outputs do not expose
sensitive internals unnecessarily.
### 11.4.5 AI Safety Checks
Assistant safety checks validate that requests outside allowed scope are constrained and
that action execution remains tool-bounded.
## 11.5 Functional Validation
Functional validation maps implemented behavior to defined requirements.
### 11.5.1 Requirement Traceability Approach
Each major requirement family is validated through scenario-based tests:
1. Authentication scenarios.
2. Scan lifecycle scenarios.
3. Findings review/reporting scenarios.
4. AI interaction scenarios.
5. Administrative governance scenarios.
### 11.5.2 Scenario Validation Examples
• A valid user can create a website scan and observe progress.
• Invalid scan payload is rejected with deterministic client error.
• Completed scans expose findings and export pathways.
• AI chat can retrieve context-aware status and guidance through bounded actions.
• Admin routes reject non-admin callers.
### 11.5.3 Functional Coverage Table
Requirement Domain Validation Outcome Type
Authentication Pass/fail by token and role conditions
Scan lifecycle Pass/fail by status transition correctness
Findings and reports Pass/fail by retrieval/export behavior
AI support Pass/fail by response/action boundaries
Admin governance Pass/fail by authorization boundary checks

## 11.6 Performance Evaluation
Performance evaluation is presented as behavior-oriented analysis rather than
unsupported absolute benchmarks.
### 11.6.1 Performance Dimensions
1. API responsiveness under normal interactive load.
2. Queue latency from dispatch to worker start.
3. Scan completion variability by target complexity and configured depth.
4. Result retrieval responsiveness for finding-heavy scans.
### 11.6.2 Factors Influencing Scan Duration
Scan duration depends on:
• Target size and route complexity.
• Number of discovered parameters/endpoints.
• Enabled modules and tool availability.
• Network latency and external service responsiveness.
Therefore, performance is evaluated through trend and behavior categories rather than
fixed universal numbers.
### 11.6.3 Scalability Implications
Queue-backed asynchronous design supports throughput improvement by adding worker
capacity. However, scaling must consider shared-state dependencies and downstream
resource bottlenecks.
## 11.7 Reliability and Failure Handling
Reliability evaluation focuses on system behavior under imperfect conditions.
### 11.7.1 Failure Scenarios
1. External tool command failure.
2. Network interruptions during scan phases.
3. Task dispatch or broker instability.
4. Partial scan phase exceptions.
5. Long-running execution timeout conditions.
### 11.7.2 Expected Reliable Behavior
Robust behavior includes:
• Controlled state transition to failed when unrecoverable.
• Persisted error message context.
• Partial result preservation where feasible.
• Continued operation in degraded mode when selected tools are unavailable.

### 11.7.3 Observability-Assisted Recovery
Logs, phase metadata, and status records are central to diagnosing and recovering from
operational failures.
### 11.7.4 Reliability Evaluation Table
Scenario Desired Behavior
Single tool unavailable Continue scan with degraded coverage
Dispatch failure Report failure transparently and preserve
trace
Mid-pipeline exception Controlled abort or partial completion
semantics
High queue pressure Maintain API responsiveness, process
backlog safely
Chat service issue Preserve scanner operation, degrade
assistive layer only
## 11.8 Chapter Summary
This chapter established a comprehensive testing and evaluation framework for SafeWeb-
AI. It described unit and integration testing priorities, security-control validation,
requirement traceability, behavior-oriented performance evaluation, and reliability
expectations under failure scenarios. The analysis demonstrates that SafeWeb-AI
evaluation is not limited to vulnerability detection output; it includes platform correctness,
safety, and operational resilience.
Chapter 12 builds on these evaluation principles to discuss observed outcomes, strengths,
limitations, and comparative interpretation.
# Chapter 12: Results and Discussion
The analytical framing in this chapter follows OWASP-aligned interpretation, practical
scanner evaluation literature, and SafeWeb-AI empirical workflow artifacts documented
across the project corpus [1], [2], [3], [49], [60], [61].
Results interpretation in this chapter is structured around Table 12.1 and prior chapter
figures/tables referenced by ID.
## 12.1 Result Framing
Results in this thesis are interpreted through an engineering-quality lens rather than
headline metrics. The objective is to evaluate whether SafeWeb-AI delivers a coherent,
usable, and extensible cybersecurity scanning workflow consistent with its design goals.

The discussion is structured around:
1. End-to-end workflow outcomes.
2. Detection and triage quality characteristics.
3. AI assistant utility boundaries.
4. Architectural strengths.
5. Current limitations and practical trade-offs.
## 12.2 Example Scan Outcomes
SafeWeb-AI executes scans that produce structured outputs including lifecycle metadata,
findings, severity categories, evidence references, and aggregated score indicators.
### 12.2.1 Workflow Completion Outcome
The platform demonstrates the intended workflow continuity:
• Target intake and validation.
• Asynchronous execution dispatch.
• Phase-aware progress updates.
• Persisted findings and report pathways.
This confirms the viability of the layered architecture as an operational pipeline.
### 12.2.2 Finding Output Characteristics
Result sets include both passive misconfiguration signals and active vulnerability-class
signals. Presentation supports filtering, prioritization, and detail inspection, which is
essential for practical remediation workflows.
### 12.2.3 Evidence and Confidence Signals
Verification and confidence-related fields improve analyst trust by distinguishing stronger
findings from lower-confidence detections.
## 12.3 Detection Quality Discussion
Detection quality is evaluated as coverage utility rather than absolute exploit-certification.
### 12.3.1 Breadth Perspective
The engine combines recon intelligence, crawler discovery, analyzer checks, tester
modules, and external tool integration. This breadth increases probability of meaningful
detection across varied target profiles.
### 12.3.2 Depth Perspective
Verification and post-processing help improve actionable depth by reducing noisy raw
output and surfacing more trustworthy findings.

### 12.3.3 Quality Caveat
No scanner can guarantee perfect detection or zero false positives. SafeWeb-AI is designed
to reduce this gap through layered processing, but expert review remains essential for
high-impact remediation decisions.
## 12.4 AI Assistant Usefulness
AI utility is evaluated by workflow assistance quality rather than novelty claims.
### 12.4.1 Observed Strengths
1. Reduced context-switching when users need scan clarification.
2. Faster interpretation of dense vulnerability outputs.
3. Practical action support through bounded function calls.
### 12.4.2 Boundaries and Cautions
1. AI responses are advisory and must be evidence-checked.
2. Safety boundaries are essential in offensive-security-adjacent contexts.
3. Deterministic scanner outputs remain authoritative for finding truth.
### 12.4.3 Net Contribution
The assistant increases usability and triage efficiency when integrated as a controlled
support layer.
## 12.5 False Positive Discussion
False-positive management is one of the most important practical outcomes in scanner
platforms.
### 12.5.1 Baseline Challenge
Rule-driven scanning can generate uncertain findings, especially in dynamic applications
with atypical response behavior.
### 12.5.2 SafeWeb-AI Mitigation Path
Mitigation combines:
• Verification passes.
• Confidence and scoring metadata.
• Correlation-aware interpretation.
• Assistive AI explanation where appropriate.
### 12.5.3 Practical Impact
These mechanisms improve analyst prioritization quality and reduce manual triage
overhead, even when complete elimination of false positives is not feasible.

## 12.6 Report Quality Discussion
Report quality is evaluated by actionability, traceability, and communication value.
### 12.6.1 Actionability
Reports that include severity, evidence, affected endpoint context, and remediation
guidance are more useful than raw scanner logs.
### 12.6.2 Traceability
Persisted scan and finding entities support reproducible reporting and historical
comparison workflows.
### 12.6.3 Stakeholder Communication
Structured reports support both technical remediation teams and non-technical
governance audiences.
## 12.7 Comparison Against Conventional Approaches
SafeWeb-AI was designed to close gaps between purely manual and purely single-engine
automated workflows.
### 12.7.1 Comparative Interpretation
Compared with manual-only practice, SafeWeb-AI improves repeatability and operational
scale. Compared with conventional scanner-only practice, it improves orchestration,
context, and structured post-processing. Compared with generic AI wrappers, it provides
stronger deterministic pipeline grounding.
### 12.7.2 Comparison Table
Dimension
Conventional Scanner
Workflow SafeWeb-AI
Orchestration depth Medium High (multi-phase)
Async scale model Variable Queue-worker centered
Verification emphasis Often limited Explicit stage
Correlation support Limited to moderate Integrated attack-chain
perspective
AI usage Optional/external Embedded bounded
assistant
Governance integration Product-dependent Role-aware platform model

## 12.8 Architectural Strengths
### 12.8.1 Modular Extensibility
The system’s modular tester and wrapper architecture allows incremental growth in
coverage without platform rewrite.
### 12.8.2 Operational Resilience
Asynchronous execution and graceful degradation improve robustness under dependency
variability.
### 12.8.3 Security-Centric Usability
Frontend and reporting surfaces are oriented toward severity-first triage and remediation
workflow support.
### 12.8.4 System Analysis Completeness
The platform is documented from requirements through deployment and evaluation,
improving academic and engineering credibility.
## 12.9 Current Limitations
A balanced thesis must report limitations explicitly.
### 12.9.1 Dependency Variability
External tools can behave differently across environments, affecting detection breadth and
reproducibility.
### 12.9.2 Target-Dependent Duration
Scan runtime remains highly dependent on attack surface size and target complexity.
### 12.9.3 Confidence Boundary
Even with verification and scoring, some findings require expert manual confirmation for
high-assurance decisions.
### 12.9.4 AI Boundary
Assistant quality depends on context quality and model behavior; it should not be treated
as autonomous security authority.
### 12.9.5 Enterprise Maturity Roadmap
Advanced enterprise controls (for example deeper multi-tenant isolation workflows and
broader compliance mapping automation) represent future maturity stages.

## 12.10 Discussion Synthesis
SafeWeb-AI demonstrates that a graduation project can exceed prototype-level
functionality by integrating architecture discipline, operational scalability, and usability-
oriented security workflows. The core contribution is not a claim of perfect detection; it is
the construction of a coherent platform where detection, verification, interpretation, and
governance are meaningfully connected.
The results indicate that multi-phase orchestration plus bounded AI assistance is a
practical direction for modern web security tooling, provided safety and evidence
boundaries remain explicit.
## 12.11 Chapter Summary
This chapter analyzed outcomes of SafeWeb-AI through workflow completion, detection
quality characteristics, false-positive handling, report usefulness, and architectural
strengths, while explicitly stating current limitations. The discussion supports the thesis
claim that SafeWeb-AI is a serious engineering platform with practical operational value
and a clear path for future maturation.
Chapter 13 concludes the thesis with contribution recap and future work roadmap.
# Chapter 13: Conclusion and Future Work
The conclusion and roadmap synthesis in this chapter is grounded in systems design
literature, secure architecture practices, and the documented implementation outcomes of
SafeWeb-AI [7], [10], [11], [46], [60], [61].
This chapter uses Table 13.1 to summarize and prioritize future roadmap directions.
## 13.1 Conclusion
This thesis presented SafeWeb-AI as an AI-assisted web application vulnerability scanning
platform designed to bridge the gap between fragmented security tooling and operationally
usable security workflows. The project addressed a central practical challenge:
organizations require broad automated coverage, but they also need confidence-aware
outputs, scalable execution, and interpretable remediation guidance.
SafeWeb-AI responded to this challenge through a layered architecture that combines a
React frontend, Django REST backend, asynchronous Celery worker execution, Redis
queueing, relational persistence, report artifact storage, and a bounded AI assistant layer.
The scanner was designed as a phased engine rather than an isolated probe set, integrating
reconnaissance, crawling, analyzer checks, vulnerability testing, verification, correlation,
and scoring.

From a system design perspective, the project demonstrated that modular decomposition
and explicit interface boundaries are essential when integrating heterogeneous external
tools and intelligence components. From a software engineering perspective, it showed the
value of asynchronous execution and lifecycle-centric modeling for reliability and
transparency in long-running security tasks. From a usability perspective, it validated that
severity-first interfaces and context-aware assistance improve triage and decision-making
quality.
The thesis also established that AI can contribute meaningful value in cybersecurity
workflows when implemented as an assistive and constrained component. In SafeWeb-AI,
deterministic scanning and verification remain the evidence backbone, while AI improves
interpretation and workflow efficiency.
## 13.2 Key Contributions Recap
### 13.2.1 Technical Contributions
1. A complete layered architecture for web vulnerability scanning at platform scale.
2. A multi-phase scanning pipeline that balances discovery breadth and evidence
quality.
3. A modular tester and external-tool wrapper ecosystem enabling extensible
coverage.
4. Verification and confidence-oriented post-processing for improved finding usability.
5. Role-aware APIs and user interfaces for both analyst and administrator workflows.
6. AI assistant integration with function-bounded actions and safety-aware behavior.
### 13.2.2 Academic Contributions
1. Full lifecycle documentation from problem definition to architecture,
implementation, and evaluation.
2. Strong alignment between system analysis artifacts and implemented modules.
3. A reproducible thesis structure suitable for future cybersecurity engineering
research.
### 13.2.3 Practical Contributions
1. Improved operational continuity through asynchronous scan execution.
2. Better triage support via structured findings and severity-based prioritization.
3. Better communication through report and dashboard workflows.
## 13.3 Practical Value
SafeWeb-AI has practical value for teams that need repeatable security assessments
integrated into broader engineering operations. It supports:
• Continuous vulnerability visibility.
• Developer-oriented remediation workflows.
• Administrative oversight and governance.
• Multi-role collaboration around security posture.

By consolidating scanning and interpretation into one platform, the system reduces tooling
fragmentation and manual orchestration overhead.
## 13.4 Research Value
The project contributes to applied cybersecurity research by showing how AI assistance
can be responsibly integrated into deterministic scanner architectures. It also illustrates
how system analysis and design principles can be concretely linked to implementation and
operations in a student-built but production-oriented artifact.
The thesis demonstrates that meaningful graduation projects in cybersecurity can move
beyond isolated feature demonstrations and deliver full-stack, operationally coherent
systems.
## 13.5 Limitations Recap
Key limitations remain:
1. External tool dependency variance can affect scan consistency across environments.
2. Runtime performance depends heavily on target complexity and scope.
3. False positives cannot be eliminated completely despite verification logic.
4. AI outputs remain advisory and require evidence-aware interpretation.
5. Advanced enterprise capabilities are roadmap items rather than fully matured in
this version.
These limitations are consistent with real-world constraints in vulnerability scanning
systems and do not invalidate the platform’s architectural contribution.
## 13.6 Future Work
Future work is structured into practical roadmap streams.
### 13.6.1 Scanning Engine Expansion
1. Add broader tester coverage for emerging web and API attack patterns.
2. Improve chain detection and multi-step exploit path confidence modeling.
3. Expand protocol and technology-specific deep test modules.
### 13.6.2 AI and Triage Maturation
1. Introduce stronger retrieval-augmented context for assistant accuracy.
2. Improve confidence calibration explanations for low/high-risk findings.
3. Add remediation validation workflows to assess fix effectiveness.
### 13.6.3 Platform and Governance Evolution
1. Strengthen multi-tenant collaboration and team workspace controls.
2. Expand compliance mapping and policy-centric reporting overlays.
3. Add deeper audit-log and approval workflows for enterprise governance.

### 13.6.4 DevOps and Cloud Evolution
1. Advance distributed worker scaling and workload isolation patterns.
2. Refine observability with richer SLO-driven alerting dashboards.
3. Expand deployment automation and rollback intelligence.
### 13.6.5 Ecosystem and Integration Growth
1. Expand webhook and integration automation pathways.
2. Develop plugin architecture for community tester and recon modules.
3. Extend SDK/API tooling for external security program integration.
### 13.6.6 Future Work Prioritization Table
Priority Horizon Future Work Focus
Near-term Engine hardening, verification refinement,
UX improvements
Mid-term AI accuracy enhancement, compliance
mapping, team workflows
Long-term Plugin ecosystem, advanced multi-tenant
architecture, broader enterprise automation
## 13.7 Final Closing Statement
SafeWeb-AI demonstrates that an academically grounded, engineering-mature
cybersecurity platform can be built as a graduation project when analysis, design,
implementation, and evaluation are treated as a coherent whole. The system provides a
credible foundation for future research and practical deployment enhancements in AI-
assisted web application security assessment.
The project affirms a central thesis outcome: effective cybersecurity tooling is not only
about finding vulnerabilities, but about building reliable systems that transform findings
into trustworthy, actionable security decisions.
References (IEEE Style)
[1] OWASP Foundation, “OWASP Top 10: The Ten Most Critical Web Application Security
Risks,” 2021. [Online]. Available: https://owasp.org/www-project-top-ten/
[2] OWASP Foundation, “Web Security Testing Guide (WSTG),” v4.2, 2021. [Online].
Available: https://owasp.org/www-project-web-security-testing-guide/v42/
[3] OWASP Foundation, “OWASP API Security Top 10,” 2023. [Online]. Available:
https://owasp.org/www-project-api-security/
[4] MITRE, “Common Weakness Enumeration (CWE),” [Online]. Available:
https://cwe.mitre.org/

[5] FIRST, “Common Vulnerability Scoring System (CVSS),” v3.1. [Online]. Available:
https://www.first.org/cvss/
[6] Open Worldwide Application Security Project, “OWASP ASVS: Application Security
Verification Standard,” [Online]. Available: https://owasp.org/www-project-application-
security-verification-standard/
[7] A. Dennis, B. H. Wixom, and D. Tegarden, Systems Analysis and Design with UML, 5th
ed. Hoboken, NJ, USA: Wiley, 2015.
[8] S. Tilley and H. Rosenblatt, Systems Analysis and Design in a Changing World, 7th
ed. Boston, MA, USA: Cengage, 2016.
[9] G. Booch, R. A. Maksimchuk, M. W. Engel, B. J. Young, J. Conallen, and K. A. Houston,
Object-Oriented Analysis and Design with Applications, 3rd ed. Boston, MA, USA: Addison-
Wesley, 2007.
[10] R. C. Martin, Clean Architecture: A Craftsman’s Guide to Software Structure and Design.
Boston, MA, USA: Prentice Hall, 2017.
[11] M. Kleppmann, Designing Data-Intensive Applications. Sebastopol, CA, USA: O’Reilly
Media, 2017.
[12] D. Meadows, Thinking in Systems: A Primer. White River Junction, VT, USA: Chelsea
Green Publishing, 2008.
[13] D. A. Norman, The Design of Everyday Things, Revised and Expanded ed. New York,
NY, USA: Basic Books, 2013.
[14] Django Software Foundation, “Django Documentation,” [Online]. Available:
https://docs.djangoproject.com/
[15] Django REST Framework, “Django REST Framework Documentation,” [Online].
Available: https://www.django-rest-framework.org/
[16] Celery Project, “Celery Documentation,” [Online]. Available: https://docs.celeryq.dev/
[17] Redis Ltd., “Redis Documentation,” [Online]. Available: https://redis.io/docs/
[18] PostgreSQL Global Development Group, “PostgreSQL Documentation,” [Online].
Available: https://www.postgresql.org/docs/
[19] React Team, “React Documentation,” [Online]. Available: https://react.dev/
[20] Vite Team, “Vite Documentation,” [Online]. Available: https://vite.dev/
[21] Tailwind Labs, “Tailwind CSS Documentation,” [Online]. Available:
https://tailwindcss.com/docs/
[22] Microsoft, “Azure Architecture Center,” [Online]. Available:
https://learn.microsoft.com/azure/architecture/

[23] Microsoft, “Azure App Service Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/app-service/
[24] Microsoft, “Azure Database for PostgreSQL Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/postgresql/
[25] Microsoft, “Azure Cache for Redis Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/azure-cache-for-redis/
[26] Microsoft, “Azure Blob Storage Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/storage/blobs/
[27] Microsoft, “Azure Key Vault Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/key-vault/
[28] Microsoft, “Application Insights Documentation,” [Online]. Available:
https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
[29] GitHub, “GitHub Actions Documentation,” [Online]. Available:
https://docs.github.com/actions
[30] PortSwigger, “Burp Suite Documentation,” [Online]. Available:
https://portswigger.net/burp/documentation
[31] Invicti Security, “Acunetix Documentation,” [Online]. Available:
https://www.acunetix.com/support/
[32] Nmap Security Scanner, “Nmap Reference Guide,” [Online]. Available:
https://nmap.org/book/man.html
[33] ProjectDiscovery, “Nuclei Documentation,” [Online]. Available:
https://docs.projectdiscovery.io/tools/nuclei/overview
[34] SQLMap Project, “SQLMap User’s Manual,” [Online]. Available:
https://github.com/sqlmapproject/sqlmap/wiki
[35] hahwul, “Dalfox Documentation,” [Online]. Available: https://dalfox.hahwul.com/
[36] ProjectDiscovery, “Subfinder Documentation,” [Online]. Available:
https://docs.projectdiscovery.io/tools/subfinder/overview
[37] OWASP Amass Project, “Amass Documentation,” [Online]. Available:
https://owasp.org/www-project-amass/
[38] Playwright Team, “Playwright Documentation,” [Online]. Available:
https://playwright.dev/docs/intro
[39] Beautiful Soup Project, “Beautiful Soup Documentation,” [Online]. Available:
https://www.crummy.com/software/BeautifulSoup/bs4/doc/
[40] Scikit-learn Developers, “Scikit-learn Documentation,” [Online]. Available:
https://scikit-learn.org/stable/documentation.html

[41] T. Chen and C. Guestrin, “XGBoost: A Scalable Tree Boosting System,” in Proc. 22nd
ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining, 2016, pp. 785-794.
[42] Google, “Gemini API Documentation,” [Online]. Available: https://ai.google.dev/
[43] OpenRouter, “OpenRouter Documentation,” [Online]. Available:
https://openrouter.ai/docs
[44] OpenAI, “Prompt Injection and LLM Safety Guidance,” [Online]. Available:
https://platform.openai.com/docs/guides/safety-best-practices
[45] National Institute of Standards and Technology, “NIST Special Publication 800-53
Rev. 5: Security and Privacy Controls,” 2020.
[46] National Institute of Standards and Technology, “NIST Cybersecurity Framework
(CSF) 2.0,” 2024.
[47] A. Yasin and L. A. M. Alzahrani, “A Survey of AI in Cybersecurity: Challenges and
Opportunities,” IEEE Access, vol. 11, pp. 1-30, 2023.
[48] M. Howard and D. LeBlanc, Writing Secure Code, 2nd ed. Redmond, WA, USA:
Microsoft Press, 2002.
[49] D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd
ed. Indianapolis, IN, USA: Wiley, 2011.
[50] C. Ball, Hacking APIs. San Francisco, CA, USA: No Starch Press, 2022.
[51] ProjectDiscovery, “httpx Documentation,” [Online]. Available:
https://docs.projectdiscovery.io/tools/httpx/overview
[52] ProjectDiscovery, “Katana Documentation,” [Online]. Available:
https://docs.projectdiscovery.io/tools/katana/overview
[53] Mozilla Foundation, “Web Security Guidelines,” [Online]. Available:
https://infosec.mozilla.org/guidelines/web_security
[54] IETF, “The OAuth 2.0 Authorization Framework,” RFC 6749, Oct. 2012.
[55] IETF, “JSON Web Token (JWT),” RFC 7519, May 2015.
[56] IETF, “HTTP Semantics,” RFC 9110, Jun. 2022.
[57] CISA, “Known Exploited Vulnerabilities Catalog,” [Online]. Available:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[58] GitHub, “Dependabot and Dependency Security Updates,” [Online]. Available:
https://docs.github.com/code-security
[59] Sonatype, “Software Supply Chain Security Best Practices,” [Online]. Available:
https://www.sonatype.com/resources

[60] SafeWeb-AI Team, “SafeWeb-AI Technical System Documentation,” Internal Project
Document, 2026.
[61] SafeWeb-AI Team, “SafeWeb-AI Repository README,” Internal Project Document,
2026.
# Appendix A: Diagram Catalog
This appendix indexes major visual assets referenced throughout the thesis.
A.1 Functional and Requirement Diagrams
1. Functional Requirements Diagram
• Source: SA & D Diagrams/1-Functional Requirements.png
2. Non-Functional Requirements Diagram
• Source: SA & D Diagrams/2-Non Functional Requirements.png
A.2 Analysis and Flow Diagrams
3. System Context (DFD Level 0)
• Source: SA & D Diagrams/3-System Context (DFD Level 0).png
4. Scan Pipeline Activity
• Source: SA & D Diagrams/5-Scan Pipeline Activity.png
5. Authentication Activity
• Source: SA & D Diagrams/6-Authentication Activity.png
A.3 Sequence Diagrams
6. Authentication Sequence
• Source: SA & D Diagrams/7-Sequence — Authentication.png
• Supplemental source: SA & D Diagrams/login sequence diagram.pdf
7. Scan Lifecycle Sequence
• Source: SA & D Diagrams/8-Sequence — Scan Lifecycle.png
• Supplemental source: SA & D Diagrams/scan sequence diagram.pdf
8. AI Chatbot Sequence
• Source: SA & D Diagrams/9-Sequence — AI Chatbot.png
9. Admin Operations Sequence
• Source: SA & D Diagrams/11-Sequence — Admin Operations.png
A.4 Architecture and Design Diagrams
10. High-Level System Architecture
• Source: SA & D Diagrams/System Architecture.png
• Supplemental source: SA & D Diagrams/high level system arch.pdf
11. System Architecture Components
• Source: SA & D Diagrams/4-System Architecture Components.png

• Supplemental source: SA & D Diagrams/system arch.pdf
12. Internal Scanner Architecture
• Source: SA & D Diagrams/internal scanner arch.pdf
13. Cloud Architecture
• Source: SA & D Diagrams/cloud system arch.pdf
A.5 UML and Data Diagrams
14. Use Case Diagram
• Source: SA & D Diagrams/11-Use Case Diagram.png
• Supplemental source: SA & D Diagrams/SafeWebAI - Use Case Diagram.pdf
15. Class Diagram
• Source: SA & D Diagrams/12-Class Diagram.png
• Supplemental source: SA & D Diagrams/class diagram.pdf
16. Detailed Class Diagram (vector source)
• Source: SA & D Diagrams/Detailed Class Diagram.svg
17. Database ERD
• Source: SA & D Diagrams/13-Database ERD.png
• Supplemental source: SA & D Diagrams/database schema.pdf
18. Detailed Database ERD (vector source)
• Source: SA & D Diagrams/Detailed Database ERD.svg
A.6 Presentation and UI Visual Evidence
19. Platform presentation deck
• Source: presentation/SafeWeb-AI-Presentation.pdf
20. UI screenshot set (responsive)
• Source: screenshots/ directory
21. Slide screenshot sequence
• Source: presentation/slides/ directory
A.7 Diagram Usage Guidance
1. PNG files are suitable for immediate embedding in thesis documents.
2. SVG files should be preferred when high-quality resizing is required.
3. PDF diagram artifacts are suitable for archival and print output.
4. Sequence and activity diagrams should be cited near corresponding process
descriptions in Chapters 3, 4, and 8.
# Appendix B: API Endpoint Index
This appendix summarizes core API surface areas exposed by SafeWeb-AI. Endpoints are
grouped by business domain for maintainability and security review.

B.1 Authentication Endpoints
Base path: /api/auth/
• POST /register/
• POST /login/
• POST /logout/
• GET/POST /verify/
• POST /refresh/
• POST /google/
• POST /forgot-password/
• POST /reset-password/
• POST /change-password/
B.2 User Profile Endpoints
Base path: /api/user/
• GET/PATCH /profile/
• GET/POST /profile/api-keys/
• DELETE /profile/api-keys/{id}/
• GET /profile/sessions/
• POST /profile/2fa/enable/
• POST /profile/2fa/verify/
B.3 Scan Lifecycle Endpoints
Base path: /api/scan/
Core lifecycle: - POST /website/ - GET /{id}/ - DELETE /{id}/delete/ - POST /{id}/rescan/ -
GET /{id}/export/ - GET /{id}/findings/ - GET /{id}/stream/
Scope workflow: - POST /{id}/resolve/ - POST /{id}/confirm/
Comparison: - GET /compare/{id1}/{id2}/
B.4 Integration and Governance Endpoints (Scan Domain)
Webhooks: - GET/POST /webhooks/ - PATCH/DELETE /webhooks/{id}/ - POST
/webhooks/{id}/test/ - GET /webhooks/{id}/deliveries/
Scopes: - GET/POST /scopes/ - PATCH/DELETE /scopes/{id}/ - POST /scopes/import/ -
POST /scopes/{id}/validate/
Scheduled scans: - GET/POST /scheduled/ - PATCH/DELETE /scheduled/{id}/
Assets: - GET /assets/ - GET/PATCH/DELETE /assets/{id}/ - GET /asset-monitor/ - POST
/asset-monitor/{id}/acknowledge/

Nuclei templates: - GET /nuclei-templates/ - POST /nuclei-templates/upload/ - PATCH
/nuclei-templates/{id}/ - DELETE /nuclei-templates/{id}/
Multi-target scans: - GET /multi/ - POST /multi/create/ - GET /multi/{id}/ - DELETE
/multi/{id}/
B.5 Dashboard Endpoints
Base path: /api/dashboard/
• GET /
• GET /trends/
B.6 Chatbot Endpoints
Base path: /api/chat/
• POST /
• GET /sessions/
• GET /sessions/{id}/
• DELETE /sessions/{id}/
• POST /messages/{id}/feedback/
• GET /suggestions/
• GET /analytics/
B.7 Admin Endpoints
Base path: /api/admin/
Representative domains: - Dashboard metrics - User management - Scan governance - ML
operations - Settings - Contact management - Job application management
B.8 API Security Notes
1. Protected endpoints require JWT authentication unless explicitly public.
2. Administrative endpoints require elevated role-based authorization.
3. Ownership checks are enforced for user-scoped resources.
4. Throttling classes are enabled at DRF configuration layer.
# Appendix C: Database Entity Reference
This appendix summarizes major entities and relationships in the SafeWeb-AI data model.
C.1 Identity and Account Entities
User
Purpose: account identity root and ownership anchor.

Representative attributes: - id (UUID) - email - role - plan - 2FA-related fields
Key relationships: - One-to-many with Scan - One-to-many with APIKey - One-to-many with
UserSession - One-to-many with ChatSession
APIKey
Purpose: programmatic access management.
UserSession
Purpose: session tracking and token-related governance metadata.
C.2 Scan Lifecycle Entities
Scan
Purpose: central lifecycle record for each assessment.
Representative attributes: - id - target - status - depth - scope_type - score -
recon_data/tester_results style fields
Key relationships: - Belongs to User - One-to-many with Vulnerability - One-to-many with
ScanReport - One-to-many with DiscoveredAsset
Vulnerability
Purpose: normalized finding record.
Representative attributes: - name - severity - category - affected_url - evidence - verified -
false_positive_score
AuthConfig
Purpose: stores scan-associated authentication configuration metadata.
ScanReport
Purpose: tracks report generation metadata and file references.
C.3 Scheduling, Scope, and Integration Entities
ScheduledScan
Purpose: recurring scan configuration.
Webhook
Purpose: event integration endpoint metadata.
WebhookDelivery
Purpose: delivery attempt tracing for webhook events.

ScopeDefinition
Purpose: reusable scope presets and target boundaries.
MultiTargetScan
Purpose: grouped scan orchestration metadata.
DiscoveredAsset
Purpose: persistence of asset intelligence discovered during scans.
AssetMonitorRecord
Purpose: tracking monitored asset changes or noteworthy events.
C.4 Conversational Intelligence Entities
ChatSession
Purpose: context container for chatbot interactions.
ChatMessage
Purpose: message-level storage with role and optional feedback/action metadata.
C.5 Administrative and Learning Entities
SystemAlert
Purpose: operational alerting and resolution state.
SystemSettings
Purpose: key-value style administrative configuration store.
Article
Purpose: learning center content model.
C.6 Relationship Overview
Parent Entity Child Entity Cardinality
User Scan One-to-many
Scan Vulnerability One-to-many
Scan ScanReport One-to-many
User APIKey One-to-many
User UserSession One-to-many
ChatSession ChatMessage One-to-many
User ScheduledScan One-to-many

Parent Entity Child Entity Cardinality
User Webhook One-to-many
C.7 Data Design Notes
1. UUID usage improves identifier unpredictability and distributed safety.
2. Hybrid relational plus flexible JSON-style fields support evolving scan artifacts.
3. Lifecycle timestamps support traceability and analytics.
4. Ownership-centered relationships reinforce authorization boundaries.
# Appendix D: Testing Artifact Index
This appendix indexes representative testing-related artifacts present in the repository and
describes their likely role in verification workflows.
D.1 Backend Scripted Test Artifacts
Representative files under backend/ include:
• test_api.py
• test_live_scan.py
• test_targeted.py
• verify_e2e.py
• check_scan.py
• check_status.py
• check_vulns.py
• debug_api.py
• diag_api.py
These files indicate iterative API and scan-path validation practices used during
development.
D.2 Result and Log Artifacts
Representative output and log artifacts include:
• test_results.txt and test_results variants
• regression output files
• scan_output and scan_err style files
• django_server_out / django_server_err
• api_test_out.txt
These artifacts suggest repeated scenario runs and result capture for troubleshooting and
regression checks.

D.3 Validation Intent Categories
Artifact Type Validation Intent
API test scripts Endpoint behavior and contract validation
Scan test scripts Pipeline behavior and finding integrity
checks
E2E verification scripts End-to-end workflow confidence
Regression result files Change-impact tracking over iterations
Runtime logs Failure analysis and operational diagnostics
D.4 Testing Documentation Recommendations
For formal defense and long-term maintainability, future revisions should align these
artifacts into a standardized testing report format:
1. Test case ID and objective.
2. Input preconditions.
3. Execution steps.
4. Expected vs observed result.
5. Pass/fail status and defect linkage.
D.5 Evidence Handling Note
This thesis references testing artifacts qualitatively and structurally. Quantitative claims
should be reported only from formally controlled test runs with reproducible environment
definitions.
# Appendix E: External Tool Wrapper Catalog
SafeWeb-AI integrates an extensive external tool ecosystem through wrapper modules.
This appendix groups the wrapper landscape by operational role.
E.1 Reconnaissance and Subdomain Intelligence
Representative tools: - subfinder - amass - assetfinder - findomain - sublist3r - chaos - dnsx
- puredns - massdns - dnsrecon
Purpose: - Expand attack surface understanding via domain and DNS intelligence.
E.2 Network and Port Discovery
Representative tools: - nmap - naabu - rustscan - masscan
Purpose: - Service discovery and exposed-port context.

E.3 Crawling and Content Discovery
Representative tools: - ffuf - feroxbuster - gobuster - dirsearch - katana - gospider -
hakrawler
Purpose: - Endpoint and content path discovery for deeper testing.
E.4 Vulnerability and Injection-Focused Tools
Representative tools: - nuclei - sqlmap - ghauri - dalfox - xsstrike - tplmap - commix -
crlfuzz - nikto
Purpose: - Signature/template checks and class-specific vulnerability probing.
E.5 CMS and Fingerprinting Tools
Representative tools: - wpscan - joomscan - whatweb - wappalyzer
Purpose: - Platform fingerprinting and CMS-specific assessment.
E.6 TLS and Transport Analysis Tools
Representative tools: - testssl - sslyze - tlsx
Purpose: - TLS posture and certificate-related security analysis.
E.7 URL and Parameter Intelligence Tools
Representative tools: - gau - waybackurls - paramspider - arjun - x8
Purpose: - Historical URL collection and parameter discovery.
E.8 Secret and Artifact Exposure Tools
Representative tools: - trufflehog - gitleaks - secretfinder
Purpose: - Secret-leak and token-pattern detection.
E.9 Cloud and Takeover-Oriented Tools
Representative tools: - cloudenum - s3scanner - awsbucketdump - subjack - subover
Purpose: - Cloud exposure and takeover signal detection.
E.10 Auxiliary and Utility Tools
Representative tools: - httpx - httprobe - interactsh - aquatone - eyewitness
Purpose: - HTTP probing, out-of-band signal handling, and optional visual reconnaissance.
E.11 Wrapper Governance Principles
1. Centralized invocation through wrapper interfaces.

2. Standardized output normalization for orchestrator consumption.
3. Graceful degradation when tools are absent or fail.
4. Scope and rate controls enforced by orchestration policy.
E.12 Catalog Summary Table
Tool Group Primary Pipeline Stage
Recon and DNS Phase 0 reconnaissance
Crawl/content discovery Phase 1 surface expansion
Vulnerability probes Phase 5 testing
Verification support tools Phase 5.5 and post-processing
Cloud/takeover checks Recon and risk enrichment
# Appendix F: Business Model Canvas (SafeWeb-AI)
This appendix documents the business and operational model of SafeWeb-AI using the
Business Model Canvas framework.
F.1 Key Partners
• Cloud infrastructure providers.
• Open-source security tool communities.
• Security research and standards organizations.
• Educational and institutional stakeholders.
• Potential enterprise integration partners.
F.2 Key Activities
• Continuous web vulnerability scanning.
• Threat and attack-surface intelligence collection.
• Vulnerability verification and prioritization.
• Report generation and remediation support.
• Platform monitoring and operational governance.
F.3 Key Resources
• Scanning engine and tester framework.
• External tool wrapper ecosystem.
• AI assistant integration layer.
• Persistent data and report storage architecture.
• Engineering team expertise across AppSec, backend, frontend, and DevOps.
F.4 Value Propositions
• Unified platform for recon, testing, verification, and reporting.
• AI-assisted interpretation of security findings.

• Real-time progress visibility with asynchronous execution.
• Extensible architecture for new vulnerability classes and integrations.
F.5 Customer Relationships
• Self-service portal for analysts and developers.
• Guided workflows and contextual AI assistance.
• Administrative oversight interfaces.
• Documentation-driven support and onboarding.
F.6 Channels
• Web application frontend.
• API endpoints for integration.
• Exportable reports for governance and developer workflows.
F.7 Customer Segments
• Security analysts and AppSec teams.
• Development teams requiring secure SDLC support.
• Academic and training environments.
• SMB and enterprise web operations teams.
F.8 Cost Structure
• Cloud hosting and managed services.
• Worker compute and scaling costs.
• Monitoring and operational tooling.
• Maintenance of external tool compatibility.
• Model/API usage costs for AI assistance.
F.9 Revenue / Impact Streams
For academic scope, primary value is security risk reduction and educational/research
impact. Potential productization pathways can include:
• Subscription tiers by scan volume and advanced features.
• Enterprise governance and compliance modules.
• API/SDK usage plans.
F.10 Business Model Summary Table
Canvas Block SafeWeb-AI Positioning
Key Partners Cloud, open-source security ecosystem,
standards bodies
Key Activities Scan orchestration, verification, reporting,
operations
Key Resources Engine, wrappers, AI layer, data and DevOps

Canvas Block SafeWeb-AI Positioning
stack
Value Proposition Unified, AI-assisted, scalable web security
platform
Customer Relationships Self-service plus guided assistance
Channels Web UI, API, report exports
Customer Segments AppSec, developers, academic and
enterprise users
Cost Structure Compute, storage, monitoring, integration
maintenance
Revenue/Impact Security posture improvement and
productization potential
# Appendix G: Requirement Traceability Matrix
This matrix maps major thesis requirements to manuscript sections to support defense
readiness and auditability.
G.1 Traceability Matrix
Requirement Theme Covered In
Background and problem framing Chapter 1, Chapter 2
Motivation and objectives Chapter 1
Contributions and scope limitations Chapter 1
OWASP and web security fundamentals Chapter 2
Existing tool and platform landscape Chapter 2
AI in cybersecurity and research gap Chapter 2
Stakeholders and FR/NFR analysis Chapter 3
Use cases, business logic, sequences,
activities
Chapter 3
Risk and constraints Chapter 3
Layered architecture and component design Chapter 4
Internal scanner architecture Chapter 4 and Chapter 8
Data architecture and database design Chapter 4 and Appendix C
Security architecture and boundaries Chapter 4 and Chapter 7
UI/UX goals and user journeys Chapter 5
Frontend implementation details Chapter 6
Backend implementation details Chapter 7
Deep scan engine implementation Chapter 8

Requirement Theme Covered In
AI/ML implementation and safety Chapter 9
Cloud and DevOps architecture Chapter 10
Testing and evaluation methodology Chapter 11
Results discussion and limitations Chapter 12
Conclusion and future roadmap Chapter 13
References References section
Figure and diagram catalog Appendix A
API index Appendix B
Testing artifact index Appendix D
External tool catalog Appendix E
Business model canvas Appendix F
G.2 Coverage Notes
1. The thesis is structured to preserve separation between analysis, design,
implementation, and evaluation.
2. Diagram references are consolidated in Appendix A to simplify review workflows.
3. Requirement coverage is intentionally redundant across core chapters where cross-
cutting concerns exist (for example security architecture across Chapters 4, 7, 8, and
10).
G.3 Review Procedure
For defense preparation, reviewers can:
1. Select a requirement theme from the matrix.
2. Navigate to mapped chapter section.
3. Validate evidence depth and consistency with referenced appendices.
# Appendix H: Figure Plates for Print
This appendix provides print-ready full-page figure plates to support defense review and
increase visual traceability in the final bound thesis version.
H.1 System and Analysis Plates
Figure H.1 Functional Requirements Diagram
Figure H.2 Non-Functional Requirements Diagram
Figure H.3 System Context (DFD Level 0)
Figure H.4 System Architecture Components

Figure H.5 Scan Pipeline Activity
Figure H.6 Authentication Activity
Figure H.7 Sequence - Authentication
Figure H.8 Sequence - Scan Lifecycle
Figure H.9 Sequence - AI Chatbot
Figure H.10 Sequence - Admin Operations
Figure H.11 Use Case Diagram
Figure H.12 Class Diagram
Figure H.13 Database ERD
Figure H.14 Detailed Class Diagram
Figure H.15 Detailed Database ERD
Figure H.16 System Architecture Overview
Figure H.17 System Architecture Variant
H.2 Presentation Plates
Figure H.18 Slide Plate 1
Figure H.19 Slide Plate 2
Figure H.20 Slide Plate 3
Figure H.21 Slide Plate 4
Figure H.22 Slide Plate 5
Figure H.23 Slide Plate 6
Figure H.24 Slide Plate 7
Figure H.25 Slide Plate 8
Figure H.26 Slide Plate 9
Figure H.27 Slide Plate 10
Figure H.28 Slide Plate 11
Figure H.29 Slide Plate 12
Figure H.30 Slide Plate 13
Figure H.31 Slide Plate 14

Figure H.32 Slide Plate 15
Figure H.33 Slide Plate 16
Figure H.34 Slide Plate 17
Figure H.35 Slide Plate 18
Figure H.36 Slide Plate 19
Figure H.37 Slide Plate 20
Figure H.38 Slide Plate 21
Figure H.39 Slide Plate 22
Figure H.40 Slide Plate 23
Figure H.41 Slide Plate 24
Figure H.42 Slide Plate 25
Figure H.43 Slide Plate 26
Figure H.44 Slide Plate 27
Figure H.45 Slide Plate 28
Figure H.46 Slide Plate 29
Figure H.47 Slide Plate 30
H.3 Print-Pagination Note
# Appendix H is intentionally structured as full-page figure plates to support print-friendly
defense review and to keep the total thesis length within the 120-150 page submission
target when rendered with thesis formatting settings.
