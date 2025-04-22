# Vulnerability-Reproduction-Secure-Coding-Patterns---Python-SQL-Injection-vulnerability
Linkedin: https://www.linkedin.com/in/mr-lopeza/
Threat Model Playbook: Amazon RDS, SQL Server (PII) via VPC
Source: https://github.com/mrlopez-ale/Vulnerability-Reproduction-Secure-Coding-Patterns---Python-SQL-Injection-vulnerability
Asset: Amazon RDS for SQL Server instance storing critical customer PII.
Environment: AWS VPC (Assumed private access from web application).
Primary Compliance Driver: LFPDPPP (Mexico).PASTA Stage I: Define Objectives & Scope
PASTA Stage I: Define Objectives & Scope:
Goal/Description: To define the business and security requirements for an Amazon RDS SQL Server database used as the primary storage for sensitive customer Personally Identifiable Information (PII) supporting a critical web application. This stage establishes the context, criticality, compliance drivers, and potential business impact of security failures, guiding the subsequent threat modeling process.Business Objectives:
Primary: Securely and reliably store, manage, and retrieve customer PII necessary for core web application functionality (e.g., authentication, profile management).
Data Accuracy: Ensure correctness and consistency of stored PII.
Performance & Availability: Provide timely access to PII data with high availability for a responsive user experience and continuous application operation.
Business Support: Enable business operations dependent on accurate customer PII (reporting, customer service).
Security Objectives (Mapped to CIA Triad + Accountability):
Confidentiality:
Prevent unauthorized access to PII data at rest (RDS encryption, TDE/Always Encrypted) and in transit (SSL/TLS).
Protect database credentials (Secrets Manager).
Prevent PII leakage via backups, logs, snapshots, replication.
Integrity:
Ensure PII accuracy and protect from unauthorized modification/deletion.
Protect against data corruption.
Maintain integrity of audit and transaction logs.
Availability:
Ensure high availability (Multi-AZ) meeting RTOs.
Ensure reliable backups and recovery (meeting RPOs).
Authentication & Authorization (Access Control):
Enforce strong, unique authentication (SQL Logins, IAM DB Auth).
Implement strict least privilege access controls for application and administrative users.
Utilize network controls (Security Groups) to restrict access within the VPC (PubliclyAccessible=false).
Auditing & Accountability (Non-Repudiation):
Enable and securely store detailed audit logs (SQL Server Audit, CloudWatch Logs, S3).
Protect audit logs from tampering and retain per requirements.
Compliance & Regulatory Drivers:
LFPDPPP (Mexico): Primary driver due to location and PII handling. Governs consent, data quality, purpose limitation, security measures, confidentiality, ARCO rights, breach notification.
GDPR: Applicable if processing EU resident data.
CCPA/CPRA: Applicable if processing California resident data.
PCI DSS: Potentially applicable if payment card data is involved.
Internal corporate security policies.
Business Impact Analysis (High-Level Summary):
A security failure involving this Critical RDS instance storing PII would result in Severe business impact:
Major PII Data Breach: Crippling fines (LFPDPPP, etc.), legal liability, mandatory notifications, severe reputational damage, loss of trust, potential license revocation.
Application Unavailability: Direct revenue loss, user service disruption, SLA penalties, negative user experience.
Data Integrity Loss: Incorrect application behavior, regulatory violations, complex remediation, loss of trust.
Financial Losses: Incident response, legal fees, penalties, compensation, extortion demands, increased operational costs, higher insurance premiums.
Compliance Violations: Significant penalties even without a breach if mandated controls are missing.
PASTA Stage II: Define Technical Scope
Goal: Identify specific technical components, data flows, trust boundaries, and potential entry points relevant to the RDS SQL Server instance storing PII.Assets:
Primary: PII data within SQL Server tables.
Secondary:
Database schema and configuration.
Database credentials (service accounts, admin accounts, IAM roles).
Database backups and snapshots (S3).
Database transaction logs.
Audit logs (SQL Server, RDS, CloudWatch Logs, S3).
Encryption keys (KMS).
RDS instance resources (compute, memory, storage).
Actors & Interacting Systems:
Web Application: Primary consumer (EC2, ECS, Lambda, etc. within VPC). Authenticates via credentials (Secrets Manager).
Database Administrators (DBAs): Humans performing management/maintenance via approved methods (bastion, VPN) using admin credentials or IAM auth.
AWS Services: IAM, VPC, Security Groups, NACLs, Secrets Manager, KMS, AWS Backup, CloudWatch, S3.
Potential Malicious Actors: External attackers, compromised internal hosts/apps, malicious insiders, compromised AWS accounts.
Technologies in Scope:
Database: Amazon RDS for SQL Server (specific version).
OS (Underlying): Managed by AWS.
Networking: AWS VPC, Subnets, Route Tables, Security Groups, NACLs.
Authentication: SQL Server Auth, potentially Windows Auth (AD), AWS IAM DB Auth.
Authorization: SQL Server Roles & Permissions.
Encryption: AWS KMS, TLS, potentially SQL Server TDE/Column-Level/Always Encrypted.
Secrets Management: AWS Secrets Manager.
Logging & Monitoring: SQL Server Audit, RDS Logs, CloudWatch Logs, CloudTrail.
Backup & Recovery: RDS Snapshots, potentially native SQL backups to S3.
Compute (Application): EC2, ECS, Lambda, etc.
Entry Points (Attack Surface):
Database Network Connection: SQL Server listener port (e.g., TCP 1433) via VPC internal network (primarily from App Security Group).
AWS Management Plane: AWS Console, API, CLI for RDS management (requires AWS creds).
Direct DB Connection Tools: SSMS, Azure Data Studio used by DBAs (requires DB creds or IAM auth).
AWS Service Integrations: Data outflow (CloudWatch, S3) or control signals (KMS, IAM).
Compromised Web Application: Becomes an entry point using its legitimate credentials.
Trust Boundaries:
VPC Perimeter (Internet <> VPC).
Web Application Instance(s) <> RDS Instance (defined by Security Groups).
DBA Workstation/Bastion <> RDS Instance (defined by network path & auth).
AWS Control Plane <> RDS Management Plane (protected by IAM).
RDS Instance <> Integrated AWS Services (KMS, S3, CloudWatch, Secrets Manager) (protected by AWS mechanisms & IAM).
Application Layer <> Database Layer (related to input validation vs. DB access controls).
Data Flows:
PII CRUD: Web App <> RDS (TCP 1433, TLS encrypted). Contains PII.
Authentication Credentials: Secrets Manager -> Web App; DBA Creds -> Tools -> RDS; IAM Creds -> IAM -> RDS.
Management/Configuration: AWS Console/API/CLI -> RDS Control Plane -> RDS Instance.
Backup Data: RDS Instance -> S3 (Encrypted via KMS).
Log Data: RDS Instance -> CloudWatch Logs / S3.
Audit Data: SQL Server Engine -> RDS Log Publishing -> CloudWatch Logs / S3.
Encryption Key Access: RDS Instance -> AWS KMS.
PASTA Stage III: Decompose Application
Goal: Break down key use cases and operational processes involving the RDS database to understand interactions and data flow from the database perspective.
Key Use Cases / Application Flows:
User Registration / Account Creation: App receives PII -> Validates -> Connects to RDS -> INSERT PII into tables -> DB enforces constraints -> Returns status.
User Login / Authentication: App receives creds -> Connects to RDS -> SELECT stored hash/salt -> App compares hashes -> (Optional) UPDATE last_login -> DB returns data/not found.
User Profile Viewing / Retrieval: Authenticated user requests profile -> App connects to RDS -> SELECT PII (filtered by user ID) -> DB returns data.
User Profile Update: Authenticated user submits changes -> App validates -> Connects to RDS -> UPDATE PII fields (targeted by user ID) -> DB applies changes -> Returns status.
PII Data Retrieval for Application Functionality: App feature needs PII -> Connects to RDS -> Executes specific SELECT (filtered) -> DB returns data.
User Account Deletion / Right to Erasure (ARCO - Cancellation): User requests deletion -> App verifies -> Connects to RDS -> Executes DELETE or status UPDATE (targeted by user ID) -> DB performs action -> Returns status.
Operational / Administrative Flows:
Database Backup / Snapshot: AWS Backup/RDS initiates -> RDS interacts with storage/control plane -> Snapshot data (incl. PII) stored encrypted in S3 (via KMS).
Database Restore / PITR: DBA initiates via AWS -> RDS retrieves snapshot/logs from S3 -> Provisions new/overwrites instance -> Requires DBA IAM permissions.
Database Schema Migration / Update: DBA connects (admin creds) -> Executes DDL (ALTER, CREATE) -> SQL Server applies changes -> Audit logs capture DDL.
Database Patching / Maintenance: AWS RDS initiates -> Applies OS/Engine patches -> May involve restart (Multi-AZ failover).
Log Retrieval / Monitoring: RDS pushes logs (Engine, Audit) to CloudWatch/S3 -> DBAs/Security access logs via AWS -> Requires IAM permissions. Metrics go to CloudWatch.
Credential Management: App retrieves creds from Secrets Manager -> Secrets Manager rotates password (updates secret & RDS) -> DBAs manage own creds.
PASTA Stage IV: Analyze Threats (STRIDE Framework)
Goal: Identify potential threats to the RDS instance and PII data, leveraging understanding from Stages I-III, categorized using STRIDE.
Threat Analysis:
Spoofing (Identity Related):
T1.1: Attacker spoofs Web Application (via stolen app creds). Impact: C, I, A.
T1.2: Attacker spoofs DBA/Admin User (via stolen DB/IAM creds). Impact: C, I, A (Full Control).
T1.3: Attacker spoofs AWS API calls (via stolen AWS creds). Impact: C, I, A (Reconfigure, Destroy).
Tampering (Data/System Modification):
T2.1: Unauthorized modification/deletion of PII (via compromised creds, SQLi). Impact: I (Data loss, LFPDPPP violation), A.
T2.2: Tampering with DB configuration (security, logging, encryption) (via compromised DBA/AWS creds). Impact: C, I (Weakened posture), R.
T2.3: Tampering with Audit Logs (SQL, CloudWatch, CloudTrail) (via compromised high-privilege DB/AWS creds). Impact: R (Undermines forensics), Compliance violation.
T2.4: Tampering with data in transit (via lack of TLS enforcement, weak TLS, MITM in VPC). Impact: C, I.
T2.5: Tampering with backups/snapshots (deletion/modification) (via compromised AWS creds). Impact: A (No recovery), I.
Repudiation (Inability to Trace Actions):
T3.1: Actions on PII cannot be traced (via disabled/insufficient logging, log tampering, shared accounts). Impact: R (Lack of accountability), Compliance violation, Hinders breach analysis.
Information Disclosure (Data Leakage/Exposure):
T4.1: Unauthorized access/exfiltration of PII (Primary Threat) (via SQLi, compromised creds, insecure backups, excessive permissions, log leakage). Impact: C (Major Breach), Compliance violation, Severe Business Impact.
T4.2: Disclosure of DB or AWS credentials (via hardcoding, insecure storage, social engineering). Impact: C (Leads to all other STRIDE threats).
T4.3: Disclosure of system config/schema (via verbose errors, reconnaissance). Impact: C (Aids attackers).
T4.4: PII leakage via insecure log handling (logging PII, insecure log storage). Impact: C, Compliance Violation.
T4.5: PII exposure from unencrypted backups/snapshots or restore process (via disabled KMS encryption, insecure export handling). Impact: C.
Denial of Service (Availability):
T5.1: Overwhelming DB (connections, queries) (via compromised creds, bad app code, network flood). Impact: A.
T5.2: DB storage exhaustion (via log growth, large imports). Impact: A.
T5.3: Deletion/corruption of critical data/objects (via compromised high-privilege creds, admin error). Impact: A, I.
T5.4: Ransomware targeting files/backups (less likely on RDS storage, possible via AWS creds on backups). Impact: A, I, potentially C.
T5.5: Network misconfiguration blocking access (via bad SG/NACL/Routing rules). Impact: A.
T5.6: Loss of access to dependencies (KMS, IAM, DNS) (via misconfiguration, AWS outage). Impact: A, potentially C.
Elevation of Privilege (Gaining Higher Permissions):
T6.1: Application service account gains higher DB privileges (via SQLi on privileged procedures, misconfigured grants). Impact: C, I, A.
T6.2: Standard DB user escalates to DBA level (via SQL Server vulnerability, misconfiguration). Impact: C, I, A (Full Control).
T6.3: User/attacker escalates privileges within AWS IAM (via IAM misconfiguration, compromised user with grant rights). Impact: C, I, A (Control over RDS management, backups, KMS).
PASTA Stage V: Vulnerability Analysis
Goal: Identify specific weaknesses and misconfigurations that could be exploited by attackers, mapping to threats from Stage IV.
Potential Vulnerabilities:
Network Configuration (VPC, SG, NACL):
V-NET-01: Overly Permissive Security Group Ingress (Allows non-essential sources). (Facilitates: T1.1, T1.2, T4.1, T5.1)
V-NET-02: Lack of Egress Filtering (Allows easy exfiltration). (Facilitates: T4.1)
V-NET-03: Publicly Accessible Instance (PubliclyAccessible=true). (Facilitates: T1.1, T1.2, T4.1, T5.1 directly from internet)
V-NET-04: Weak Network Segmentation (Compromise anywhere can reach DB path). (Increases likelihood of internal T1, T4, T5)
RDS Instance & SQL Server Configuration:
V-RDS-01: Encryption-at-Rest Disabled/Weakened (No KMS or weak key policy). (Facilitates: T4.1, T4.5)
V-RDS-02: TLS Not Enforced (rds.force_ssl=0). (Facilitates: T2.4, T4.1)
V-RDS-03: Weak TLS Configuration (Outdated protocols/ciphers). (Facilitates: T2.4, T4.1)
V-RDS-04: Backups Disabled or Insufficient (Retention too short, not tested). (Facilitates: T5.3, T5.4 impact)
V-RDS-05: Multi-AZ Disabled. (Facilitates: T5.1, T5.6 impact)
V-SQL-01: Weak Database Password Policies (Complexity, history, expiration). (Facilitates: T1.1, T1.2)
V-SQL-02: Excessive Database Permissions (App/DBA has db_owner/sysadmin). (Facilitates: T2.1, T4.1, T5.3, T6.1, T6.2 impact)
V-SQL-03: Audit Logging Disabled or Insufficient (Not capturing critical events). (Facilitates: T3.1, hinders detection)
V-SQL-04: Unnecessary Features Enabled (Increases attack surface). (Potentially facilitates: T6.2)
V-SQL-05: Lack of Granular Data Encryption (No TDE/Always Encrypted when needed). (Potential gap for: T4.1)
V-RDS-06: Delayed Patching (Not applying available patches promptly). (Potentially facilitates: T6.2)
Authentication, Authorization & Credential Management:
V-AUTH-01: Insecure Credential Storage (Application) (Hardcoded, plain text). (Facilitates: T1.1)
V-AUTH-02: Secrets Manager Misconfiguration (Permissive policy, no rotation). (Facilitates: T1.1)
V-AUTH-03: Shared Database Accounts (Multiple apps/users use same login). (Facilitates: T3.1)
V-AUTH-04: Lack of IAM Database Authentication (Missed opportunity for better auth).
V-IAM-01: Weak IAM Policies (Overly permissive rds:*, s3:*, kms:*, logs:*). (Facilitates: T1.3, T2.2, T2.5, T4.5, T5.3, T6.3)
V-IAM-02: Lack of MFA (For privileged AWS/DBA access). (Increases likelihood of: T1.2, T1.3)
Logging, Monitoring & Alerting:
V-LOG-01: Insufficient Log Retention (Too short for forensics/compliance). (Facilitates: T3.1)
V-LOG-02: Insecure Log Storage (Permissive access to CloudWatch/S3 logs). (Facilitates: T2.3, T4.4)
V-LOG-03: Lack of Security Alerting (No alarms on critical events). (Hinders detection of T1-T6)
Application Layer:
V-APP-01: SQL Injection (SQLi) (No parameterized queries/sanitization). (Critical: Facilitates T1.1, T2.1, T4.1, T5.1, T6.1)
V-APP-02: Improper Error Handling (Reveals detailed DB errors). (Facilitates: T4.3)
Backup and Recovery:
V-BCK-01: Unencrypted Backups/Exports (To S3 without SSE). (Facilitates: T4.5)
V-BCK-02: Insecure Backup Storage Access (Permissive S3 policies). (Facilitates: T4.5, T2.5)
V-BCK-03: Untested Restore Procedures (Uncertainty of RTO/RPO). (Increases impact of T5)
Compliance-Specific (LFPDPPP Example):
V-CMP-01: Inability to Fulfill ARCO Rights (No process/tech for delete/rectify/access). (Compliance violation, potential I issues)
V-CMP-02: Inadequate Data Retention Controls (No deletion of old PII). (Compliance violation, increases T4.1 scope)
PASTA Stage VI: Attack Modeling
Goal: Simulate potential attack paths adversaries could take to exploit vulnerabilities (Stage V) and realize threat objectives (Stage IV).
Example Attack Scenarios / Paths:
Scenario 1: PII Exfiltration via Web Application SQL Injection
Goal: Steal PII (T4.1).
Path: Attacker finds input -> Exploits SQLi (V-APP-01) -> Uses injected queries (UNION, error-based) to discover schema -> Extracts PII via SELECT -> Exfiltrates via app responses.
Vulnerabilities: V-APP-01 (Primary). Impact amplified by V-SQL-02 (Excessive Permissions).
Scenario 2: PII Exfiltration via Compromised Application Server / Credentials
Goal: Steal PII (T4.1).
Path: Attacker compromises app server -> Finds insecure DB creds (V-AUTH-01) -> Connects directly to RDS (possible via V-NET-01) (Spoofing T1.1) -> Runs SELECT queries -> Exfiltrates data (easier with V-NET-02).
Vulnerabilities: V-AUTH-01, V-NET-01, V-NET-02.
Scenario 3: Malicious PII Tampering via Compromised Privileged Account
Goal: Modify/delete PII (T2.1).
Path: Attacker compromises DBA/Admin creds (via phishing, weak auth V-IAM-02/V-SQL-01) (Spoofing T1.2) -> Connects with high privileges (V-SQL-02) -> Executes UPDATE/DELETE on PII -> (Optional) Attempts to tamper logs (V-SQL-03, V-LOG-02) (Repudiation T3.1).
Vulnerabilities: V-IAM-02/V-SQL-01, V-SQL-02, potentially V-SQL-03, V-LOG-02.

Purpose: Visualize threats, prioritize mitigations, assess control effectiveness, inform detection rules.
PASTA Stage VII: Risk Analysis & Mitigation
Goal: Analyze risks associated with threats/vulnerabilities and propose specific countermeasures aligned with security objectives and compliance.
Risk Analysis Summary: Threats leading to PII data breaches (T4.1), major data integrity issues (T2.1), extended DoS (T5), or compliance failures (LFPDPPP) represent the highest risks due to severe business impact.
Proposed Mitigations / Countermeasures:
Network Security (Address V-NET-*):
Strict Security Groups: Ingress only from App SG on required port. Deny all else.
PubliclyAccessible=false: Ensure and audit this setting.
Egress Filtering: Restrict outbound connections from app servers/NACLs.
VPC Endpoints: Use for AWS service communication (Secrets Manager, S3, KMS, CloudWatch).
RDS Instance & SQL Server Config (Address V-RDS-, V-SQL-):
Enable Encryption-at-Rest: Use KMS Customer Managed Key (CMK) with strong key policy.
Enforce TLS: Set rds.force_ssl=1. Use strong TLS protocols/ciphers (TLS 1.2+).
Enable Multi-AZ: Ensure high availability.
Configure Automated Backups: Set appropriate retention (RPO, compliance). Test restores regularly.
Strong SQL Password Policies: Enforce complexity, history, expiration. Avoid sa.
Least Privilege (Database): Minimal permissions for app account (specific table CRUD). Specific roles for DBAs, avoid blanket sysadmin.
Enable SQL Server Audit: Capture critical events (logins, failed logins, DDL, PII DML, security changes). Publish securely to CloudWatch/S3.
Timely Patching: Apply RDS patches during maintenance windows.
Consider Native Encryption: Use Always Encrypted/TDE if needed for defense-in-depth.
Authentication, Authorization & Credential Mgmt (Address V-AUTH-, V-IAM-):
Use AWS Secrets Manager: Store app DB creds, enable rotation, minimal IAM permissions for retrieval. NO HARDCODING.
Use IAM DB Authentication: Prefer for human users (DBAs) for integration.
Enforce MFA: For privileged AWS Console/CLI access.
Least Privilege (IAM): Granular policies for RDS, S3, KMS, CloudWatch access. Audit regularly.
Logging, Monitoring & Alerting (Address V-LOG-*):
Adequate Log Retention: Set CloudWatch/S3 retention per compliance/forensics needs.
Secure Log Storage: Strict policies/ACLs on CloudWatch Log Groups / S3 buckets. Encrypt logs in S3.
Implement Security Alerting: CloudWatch Alarms/EventBridge for failed logins, config changes (CloudTrail), critical SQL audit events, resource exhaustion, public access changes, failovers.
Application Layer Security (Address V-APP-*):
Prevent SQL Injection: MANDATE parameterized queries/prepared statements/safe ORMs. Validate input. Use SAST/DAST. Consider WAF.
Generic Error Messages: Log details server-side only.
Backup and Recovery Security (Address V-BCK-*):
Encrypt Backups/Exports: Ensure snapshots use KMS CMK. Use SSE-KMS/SSE-S3 for native backups to S3.
Secure Backup Storage: Strict, least-privilege S3 bucket policies. Consider S3 Object Lock.
Regular Restore Testing: Validate backups and RTO/RPO.
Compliance Specific (LFPDPPP) (Address V-CMP-*):
Facilitate ARCO Rights: Design schema/processes for Access, Rectification, Cancellation, Opposition. Secure deletion procedures.
Enforce Data Retention Policies: Implement mechanisms to delete/anonymize PII when no longer needed.
Align & Document Controls: Ensure technical measures meet LFPDPPP requirements and document them.
Residual Risk & Continuous Improvement: Implement controls, but residual risk remains. Maintain continuous security posture management: regular audits, vulnerability scanning, penetration testing, log reviews, adapt controls to evolving threats/services. Stay informed on best practices.
