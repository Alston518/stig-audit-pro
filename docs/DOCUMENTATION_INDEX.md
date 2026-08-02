# STIG Audit Pro documentation

## Product and operator documents

- [Product overview](PRODUCT_OVERVIEW.md) - official product description, scope, bundled coverage, licensing, outputs, and limitations.
- [Command reference and device-change statement](COMMAND_REFERENCE.md) - exact bundled commands, session operations, full-collection catalog, sample behavior, and custom-pack boundary.
- [Administrator guide](ADMINISTRATOR_GUIDE.md) - authorization, license checks, operation, result interpretation, evidence handling, and Administrator-only remediation workflow.
- [Security and data handling](SECURITY_AND_DATA_HANDLING.md) - Target Device safety boundary, raw command cache, credentials, network connections, offline licensing, and deployment controls.
- [Offline licensing operations](OFFLINE_LICENSING.md) - customer license locations, publisher key custody, license issuance, build verification, and acceptance tests.
- [Root Guard configuration](ROOT_GUARD_CONFIGURATION.md) - CDP-based Root Guard profile and check behavior.
- [Root Guard setup guide](../ROOT_GUARD_SETUP_GUIDE.md) - repository-level deployment guidance.
- [Tester getting started](../TESTER_GETTING_STARTED.md) - pilot testing workflow.
- [Enterprise roadmap](../ENTERPRISE_ROADMAP.md) - planned product work and release direction.

## Legal and release documents

- [End User License Agreement](EULA.md) - formal draft that requires completion and counsel approval before distribution.
- [Release and legal-readiness checklist](RELEASE_LEGAL_CHECKLIST.md) - product-owner actions required before external release.

## Core assurance statement

The unmodified version 0.1.0 product and bundled check packs use a maximum of nine documented Cisco IOS-XE `show` commands plus the non-persistent `terminal length 0` session setting. If an Administrator supplies an enable secret, the session may first enter privileged EXEC mode; it never enters configuration mode. The product makes zero changes to an audited device's running or startup configuration and provides no remediation path. Any configuration or operational change considered after a scan is an independent decision and action of authorized administrative personnel outside the product.
