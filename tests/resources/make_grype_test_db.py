#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

"""Generate the minimal grype vulnerability DB used by the integration tests.

The output is tests/resources/grype-test-db.tar.gz — a ~2 KB archive
containing an empty SQLite database with one synthetic CVE entry. Committing
this artifact avoids the ~50 s cold-cache grype DB download during test runs.

Schema target: grype DB model version 6 (grype v0.79+).
  Find the current model: grype db status | grep Schema
  or: SELECT model FROM db_metadata;  in a freshly downloaded DB.

When grype bumps the model integer:
  1. Update MODEL below to match.
  2. Verify the vulnerability and affected-CPE blob JSON schemas against
     grype's source (db/v6/models/) or a live DB row.
  3. Re-run this script and commit the updated grype-test-db.tar.gz.

Synthetic CVE: CVE-TEST-2026-00001 affects sbomnix-test-first == 1.0.
Grype matches pkg:nix packages via auto-generated CPEs (--add-cpes-if-none).
The generated CPE for 'sbomnix-test-first' 1.0 is:
  cpe:2.3:a:sbomnix-test-first:sbomnix-test-first:1.0:*:*:*:*:*:*:*
so the DB entry uses vendor=product='sbomnix-test-first'.
"""

import json
import sqlite3
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_ARCHIVE = HERE / "grype-test-db.tar.gz"
MODEL = 6
REVISION = 1
ADDITION = 4
SYNTHETIC_CVE = "CVE-TEST-2026-00001"
TEST_PACKAGE = "sbomnix-test-first"
TEST_VERSION = "1.0"

VULN_BLOB = json.dumps(
    {
        "id": SYNTHETIC_CVE,
        "assigner": ["test"],
        "description": (
            "Synthetic vulnerability for sbomnix grype integration tests. "
            "Not a real CVE."
        ),
        "refs": [],
        "severities": [
            {
                "scheme": "CVSS",
                "value": {"vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P", "version": "2.0"},
                "source": "test",
                "rank": 1,
            }
        ],
    }
)

# Blob linked from affected_cpe_handles; constraint targets the test version.
AFFECTED_CPE_BLOB = json.dumps(
    {
        "cves": [SYNTHETIC_CVE],
        "ranges": [{"version": {"constraint": f"= {TEST_VERSION}"}}],
    }
)

# Exact DDL as created by grype — constraint names must match for migration.
DDL = """
CREATE TABLE `affected_cpe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`cpe_id` integer,`blob_id` integer,CONSTRAINT `fk_affected_cpe_handles_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`),CONSTRAINT `fk_affected_cpe_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`));
CREATE TABLE `affected_package_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`operating_system_id` integer,`package_id` integer,`blob_id` integer,CONSTRAINT `fk_affected_package_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_affected_package_handles_operating_system` FOREIGN KEY (`operating_system_id`) REFERENCES `operating_systems`(`id`),CONSTRAINT `fk_affected_package_handles_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `blobs` (`id` integer PRIMARY KEY AUTOINCREMENT,`value` text NOT NULL);
CREATE TABLE `cpes` (`id` integer PRIMARY KEY AUTOINCREMENT,`part` text NOT NULL,`vendor` text,`product` text NOT NULL,`edition` text,`language` text,`software_edition` text,`target_hardware` text,`target_software` text,`other` text);
CREATE TABLE `cwe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`cwe` text NOT NULL,`source` text,`type` text);
CREATE TABLE `db_metadata` (`build_timestamp` datetime NOT NULL,`model` integer NOT NULL,`revision` integer NOT NULL,`addition` integer NOT NULL);
CREATE TABLE `epss_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`epss` real NOT NULL,`percentile` real NOT NULL);
CREATE TABLE `epss_metadata` (`date` datetime NOT NULL);
CREATE TABLE `known_exploited_vulnerability_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`blob_id` integer);
CREATE TABLE `operating_system_specifier_overrides` (`alias` text,`version` text,`version_pattern` text,`codename` text,`channel` text,`replacement` text,`replacement_major_version` text,`replacement_minor_version` text,`replacement_label_version` text,`replacement_channel` text,`rolling` numeric,`applicable_client_db_schemas` text,PRIMARY KEY (`alias`,`version`,`version_pattern`,`replacement`,`replacement_major_version`,`replacement_minor_version`,`replacement_label_version`,`replacement_channel`,`rolling`));
CREATE TABLE `operating_systems` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text,`release_id` text,`major_version` text,`minor_version` text,`label_version` text,`codename` text,`channel` text,`eol_date` datetime,`eoas_date` datetime);
CREATE TABLE `package_cpes` (`cpe_id` integer,`package_id` integer,PRIMARY KEY (`cpe_id`,`package_id`),CONSTRAINT `fk_package_cpes_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`),CONSTRAINT `fk_package_cpes_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `package_specifier_overrides` (`ecosystem` text,`replacement_ecosystem` text,PRIMARY KEY (`ecosystem`,`replacement_ecosystem`));
CREATE TABLE `packages` (`id` integer PRIMARY KEY AUTOINCREMENT,`ecosystem` text,`name` text);
CREATE TABLE `providers` (`id` text,`version` text,`processor` text,`date_captured` datetime,`input_digest` text,PRIMARY KEY (`id`));
CREATE TABLE `unaffected_cpe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`cpe_id` integer,`blob_id` integer,CONSTRAINT `fk_unaffected_cpe_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_unaffected_cpe_handles_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`));
CREATE TABLE `unaffected_package_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`operating_system_id` integer,`package_id` integer,`blob_id` integer,CONSTRAINT `fk_unaffected_package_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_unaffected_package_handles_operating_system` FOREIGN KEY (`operating_system_id`) REFERENCES `operating_systems`(`id`),CONSTRAINT `fk_unaffected_package_handles_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `vulnerability_aliases` (`name` text,`alias` text NOT NULL,PRIMARY KEY (`name`,`alias`));
CREATE TABLE `vulnerability_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL,`status` text NOT NULL,`published_date` datetime,`modified_date` datetime,`withdrawn_date` datetime,`provider_id` text NOT NULL,`blob_id` integer,CONSTRAINT `fk_vulnerability_handles_provider` FOREIGN KEY (`provider_id`) REFERENCES `providers`(`id`));
"""


def build(db_path: Path) -> None:
    db_path.unlink(missing_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(DDL)
    con.execute(
        "INSERT INTO db_metadata VALUES (datetime('now'), ?, ?, ?)",
        (MODEL, REVISION, ADDITION),
    )
    con.execute(
        "INSERT INTO providers VALUES ('test', '1', 'test', datetime('now'), "
        "'xxh64:0000000000000000')"
    )
    # Vulnerability detail blob (blob_id=1)
    con.execute("INSERT INTO blobs(value) VALUES (?)", (VULN_BLOB,))
    # Affected-CPE constraint blob (blob_id=2)
    con.execute("INSERT INTO blobs(value) VALUES (?)", (AFFECTED_CPE_BLOB,))
    con.execute(
        "INSERT INTO vulnerability_handles"
        "(name, status, published_date, modified_date, provider_id, blob_id)"
        " VALUES (?, 'active', datetime('now'), datetime('now'), 'test', 1)",
        (SYNTHETIC_CVE,),
    )
    # CPE: cpe:2.3:a:sbomnix-test-first:sbomnix-test-first:*:*:*:*:*:*:*:*
    con.execute(
        "INSERT INTO cpes(part, vendor, product) VALUES ('a', ?, ?)",
        (TEST_PACKAGE, TEST_PACKAGE),
    )
    con.execute(
        "INSERT INTO affected_cpe_handles(vulnerability_id, cpe_id, blob_id)"
        " VALUES (1, 1, 2)"
    )
    con.commit()
    con.close()


def main() -> None:
    db_path = HERE / "vulnerability.db"
    build(db_path)
    print(f"DB: {db_path.stat().st_size // 1024} KB")
    with tarfile.open(OUT_ARCHIVE, "w:gz") as tf:
        tf.add(db_path, arcname="vulnerability.db")
    db_path.unlink()
    print(f"Archive: {OUT_ARCHIVE.stat().st_size // 1024} KB → {OUT_ARCHIVE}")


if __name__ == "__main__":
    main()
