https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/cloud-native-security-whitepaper.md

# Overview of Cloud Native Security (14%)
* The 4Cs of Cloud Native Security
  * https://medium.com/@dmosyan/the-4cs-of-cloud-native-kubernetes-security-958c720e2391
  * https://www.tigera.io/learn/guides/cloud-native-security/
* Cloud Provider and Infrastructure Security
  * https://www.strongdm.com/blog/cloud-infrastructure-security
  * https://www.aquasec.com/cloud-native-academy/cspm/cloud-infrastructure-security/
* Controls and Frameworks: https://www.aquasec.com/cloud-native-academy/cspm/cloud-security-controls/
  * Controls:
    * deterrent: Discourage potential attackers by signaling that robust security measures are in place
    * preventive: Prevent security incidents. Examples: network policy, rbac
    * detective: Identify security incidents when they occur. Example: Falco, tetragon, tracee
    * corrective: Act after an incident to minimize damage. Example Tetragon
  * Security Frameworks :
    * NIST (National Institute of Standards and Technology) Cybersecurity Framework
    * CIS (Center for Internet Security) Controls
    * ISO/IEC 27001
    * TUF: https://theupdateframework.io/
  * Cloud Native Frameworks :
    * KSPM:
      * https://medium.com/@clouddefenseai/kubernetes-security-posture-management-kspm-explained-d692c2aed103
      * https://www.aquasec.com/blog/kspm-kubernetes-security-posture-management/
      * Example Aqua Security, sysdig Secure, Snyk
    * CSA Cloud Controls Matrix (CCM) : https://cloudsecurityalliance.org/blog/2020/10/16/what-is-the-cloud-controls-matrix-ccm
* Isolation Techniques
    https://kubernetes.io/docs/concepts/security/multi-tenancy/#isolation
     https://dev.to/thenjdevopsguy/4-methods-of-kubernetes-isolation-5fc2
    * Namespace: https://www.aquasec.com/cloud-native-academy/kubernetes-101/kubernetes-namespace/
    * Pod: https://www.aquasec.com/blog/kubernetes-security-pod-escape-log-mounts/
    * Container
    * Network Policy:
      * https://kubernetes.io/docs/concepts/services-networking/network-policies/
      * https://editor.networkpolicy.io/
    * RBAC:
      * https://kubernetes.io/docs/reference/access-authn-authz/rbac/
      * FR: https://blog.stephane-robert.info/post/kubernetes-gestion-access-rbac/
      * https://octopus.com/blog/k8s-rbac-roles-and-bindings
      * https://security.padok.fr/en/blog/role-based-access-kubernetes
      * FR: https://www.ambient-it.net/rbac-kubernetes/
      * https://www.aquasec.com/cloud-native-academy/kubernetes-101/kubernetes-rbac/
    * Mesh services: mtls
    * Node: https://kubernetes.io/docs/concepts/security/multi-tenancy/#node-isolation
* Artifact Repository and Image Security
  * Artifact Repository: 
    * https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/cloud-native-security-whitepaper.md#artifact-registries
  * Image Security:
    * https://kubernetes.io/docs/concepts/containers/images/
    * https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
      * https://docs.docker.com/reference/cli/docker/scout/
    * https://docs.docker.com/develop/security-best-practices/
* Workload and Application Code Security
  * SAST DAST : https://circleci.com/blog/sast-vs-dast-when-to-use-them/
  * Cloud Workload Protection Platforms (CWPP) : https://www.aquasec.com/cloud-native-academy/cspm/cwpp-security-what-you-should-know/

# Kubernetes Cluster Component Security (22%)
* https://dev.to/thenjdevopsguy/kcsa-part-3-kubernetes-cluster-component-security-4o6d
* https://www.cncf.io/blog/2021/08/20/how-to-secure-your-kubernetes-control-plane-and-node-components/
* https://kubernetes.io/docs/concepts/security/security-checklist/
* Control Plane
  * API Server
    * https://kubernetes.io/docs/concepts/security/controlling-access/
  * Controller Manager
    * https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/
  * Scheduler
    * https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/
  * Etcd
    * https://www.aquasec.com/cloud-native-academy/kubernetes-in-production/kubernetes-security-best-practices-10-steps-to-securing-k8s/#Protect-etcd-with-TLS,-Firewall-and-Encryption
* Worker node
  * Kubelet
    * https://www.aquasec.com/cloud-native-academy/kubernetes-in-production/kubernetes-security-best-practices-10-steps-to-securing-k8s/#Lock-Down-Kubelet
  * Container Runtime
  * KubeProxy
    * https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/
    * https://www.kubernetes.dev/blog/2024/01/05/kube-proxy-non-privileged/
  * Pod
    * https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    * https://kubernetes.io/docs/tasks/configure-pod-container/assign-cpu-resource/
    * https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/
    * https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/
  * Container Networking
  * Client Security
  * Storage

# Kubernetes Security Fundamentals (22%)
* Pod Security Standards
  * https://kubernetes.io/docs/concepts/security/pod-security-standards/
  * https://snyk.io/blog/understanding-kubernetes-pod-security-standards/
  * https://www.eksworkshop.com/docs/security/pod-security-standards/
* Pod Security Admissions
  * https://kubernetes.io/docs/concepts/security/pod-security-admission/
* Authentication
  * https://kubernetes.io/docs/reference/access-authn-authz/authentication/
  * https://kubernetes.io/docs/concepts/security/hardening-guide/authentication-mechanisms/
* Authorization
  * https://kubernetes.io/docs/reference/access-authn-authz/authorization/
* Secrets
  * https://kubernetes.io/docs/concepts/configuration/secret/
  * https://www.aquasec.com/cloud-native-academy/supply-chain-security/secrets-management/
* Isolation and Segmentation
  * https://kubernetes.io/docs/concepts/security/multi-tenancy/#isolation
* Audit Logging
  * https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
* Network Policy
  * https://kubernetes.io/docs/concepts/services-networking/network-policies/

# Kubernetes Threat Model (16%)
* https://docs.cilium.io/en/stable/security/threat-model/
* https://www.aquasec.com/cloud-native-academy/vulnerability-management/mitre-attack/

* Kubernetes Trust Boundaries and Data Flow
  * https://kubernetes.io/docs/concepts/architecture/control-plane-node-communication/
* Persistence
  * https://www.redhat.com/en/blog/protecting-kubernetes-against-mitre-attck-persistence
* Denial of Service
  * https://www.tigera.io/blog/how-to-detect-and-stop-ddos-attacks-in-a-kubernetes-environment/
* Malicious Code Execution and Compromised Applications in Containers
* Attacker on the Network
* Access to Sensitive Data
* Privilege Escalation

# Platform Security (16%)
* Supply Chain Security: https://www.cncf.io/blog/2022/04/12/a-map-for-kubernetes-supply-chain-security/
  * SLSA Framework: https://slsa.dev/
  * SBOM
  * Sigstore
  * Dependancy check
  * Image Signature
  * Secured Build
  * Build Chain
* Image Repository
  * RBAC
  * Image analysed (trivy, clair)
  * Pull image policy (always, ifnopresent, never)
  * Image signed
* Observability
  * logging (elastic search)
  * metrics (prometheus)
  * tracing (jaeger)
  * alerting
* Service Mesh: https://linkerd.io/what-is-a-service-mesh/
  * mtls
  * traffic control
  * observability
  * resilience: Implement fault-tolerant techniques like circuit breakers, retries, and load balancing.
* PKI: https://kubernetes.io/docs/setup/best-practices/certificates/
  * TLS Certificates
  * Certificate Rotation
  * Key Management
  * ACME Protocol (cert manager)
* Connectivity: https://kubernetes.io/docs/concepts/cluster-administration/networking/
  * Network Policies
  * CNI Plugins
  * Encrypting Data
  * Network Segmentation
* Admission Control: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
  * Admission Controllers (PodSecurityPolicy)
  * OPA/Gatekeeper or Kyverno
  * Audit logs

# Compliance and Security Frameworks (10%)
* Compliance Frameworks
  * CIS Benchmarks
  * NIST SP 800-53
    * https://www.cyberlands.io/nistcsfandkubernetesformicroservicesenvironments
    * https://www.tigera.io/blog/deep-dive/implement-nist-cybersecurity-framework-with-calico-to-reduce-security-risks-in-kubernetes-environments/
    * FR: https://www.c-risk.com/fr/blog/nist-cybersecurity-framework
  * PCI DSS
  * HIPAA
* Threat Modelling Frameworks
  FR: https://positivethinking.tech/fr/insights-fr/threat-modeling-quelle-methode-choisir-pour-votre-entreprise-stride-dread-qtmm-linddun-pasta/
  * STRIDE : Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    * https://en.wikipedia.org/wiki/STRIDE_model
    * https://dev.to/pbnj/demystifying-stride-threat-models-230m
  * DREAD : Damage, Reproducibility, Exploitability, Affected Users, Discoverability
  * PASTA : Process for Attack Simulation and Threat Analysis
  * MITRE ATT&CK : MITRE Adversarial Tactics, Techniques, and Common Knowledge
  * OWASP Top ten : Open Web Application Security Project Top Ten
  * LINDDUN : Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance
* Supply Chain Compliance
  * SLSA
  * SBOM
  * Dependency Management
* Automation and Tooling 
  * CI/CD Integration
  * Policy Enforcement
  * Security Scanning
  * Audit and Logging
