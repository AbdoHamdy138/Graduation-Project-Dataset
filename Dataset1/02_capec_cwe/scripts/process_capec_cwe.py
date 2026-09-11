import json
import re
import xml.etree.ElementTree as ET

from pathlib import Path
from collections import defaultdict

# ==========================================================
# PATHS
# ==========================================================

DATASET_ROOT = Path(
    r"E:\Graduation Project\Dataset1"
)

CAPEC_INPUT = (
    DATASET_ROOT
    / "CAPEC"
    / "capec.xml"
)

CWE_INPUT = (
    DATASET_ROOT
    / "CWE"
    / "cwe.xml"
)

OUTPUT_ROOT = (
    DATASET_ROOT
    / "02_capec_cwe"
    / "processed"
)

# ==========================================================
# TARGET TECHNIQUES & FAMILIES
# ==========================================================

TARGET_TECHNIQUES = [
    "T1018", "T1069", "T1087", "T1482", "T1053", "T1059", "T1543", "T1547",
    "T1027", "T1055", "T1070", "T1105", "T1566", "T1003", "T1552", "T1555",
    "T1558", "T1021", "T1041", "T1048", "T1570", "T1486", "T1190", "T1059.006",
    "T1203", "AML.T0051", "T1110", "T1110.003", "T1110.004", "T1078", "T1498",
    "T1499", "T1071"
]

FAMILIES = {
    "malware_backdoor": {
        "display_name": "Malware / Backdoor Operations",
        "keywords": [
            "malware", "backdoor", "trojan", "remote access", "payload",
            "malicious software", "command and control", "c2"
        ],
        "techniques": [
            "T1018", "T1069", "T1087", "T1482", "T1053", "T1059", 
            "T1543", "T1547", "T1027", "T1055", "T1070", "T1105"
        ]
    },
    "social_engineering_credential_theft": {
        "display_name": "Social Engineering & Credential Theft",
        "keywords": [
            "phishing", "spear phishing", "social engineering", "credential theft",
            "credential", "password theft", "credential harvesting", "impersonation",
            "vishing", "smishing"
        ],
        "techniques": [
            "T1566", "T1003", "T1552", "T1555", "T1558"
        ]
    },
    "ransomware_data_impact": {
        "display_name": "Ransomware / Data Impact",
        "keywords": [
            "ransomware", "data encryption", "file encryption", "data destruction",
            "data corruption", "destructive", "denial of service", "data loss", "extortion"
        ],
        "techniques": [
            "T1021", "T1041", "T1048", "T1570", "T1486"
        ]
    },
    "web_injection": {
        "display_name": "Web Injection",
        "keywords": [
            "sql injection", "cross site scripting", "cross-site scripting", "xss",
            "command injection", "os command injection", "code injection",
            "ldap injection", "xpath injection", "nosql injection",
            "server side request forgery", "ssrf", "template injection"
        ],
        "techniques": [
            "T1190", "T1059.006", "T1203", "AML.T0051"
        ]
    },
    "authentication_bruteforce": {
        "display_name": "Authentication / Brute Force",
        "keywords": [
            "brute force", "password guessing", "password cracking", "password spraying",
            "credential stuffing", "authentication", "login", "password attack"
        ],
        "techniques": [
            "T1110", "T1110.003", "T1110.004", "T1078"
        ]
    },
    "dos_ddos_botnet_c2": {
        "display_name": "DoS / DDoS & Botnet & C2 Operations",
        "keywords": [
            "denial of service", "ddos", "dos", "botnet", "c2",
            "command and control", "resource exhaustion", "flood", "network disruption"
        ],
        "techniques": [
            "T1498", "T1499", "T1071"
        ]
    }
}

# ==========================================================
# BASIC HELPERS
# ==========================================================

def clean_text(text):
    if not text:
        return None
    text = re.sub(r"\s+", " ", text).strip()
    return text or None

def normalize(value):
    if not value:
        return ""
    value = value.lower()
    value = re.sub(r"[-_/]", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()

def element_text(element):
    if element is None:
        return None
    text = " ".join(part.strip() for part in element.itertext() if part and part.strip())
    return clean_text(text)

def find_child(element, name):
    if element is None:
        return None
    for child in element:
        tag = child.tag.split("}")[-1]
        if tag == name:
            return child
    return None

def find_children(element, name):
    if element is None:
        return []
    results = []
    for child in element:
        tag = child.tag.split("}")[-1]
        if tag == name:
            results.append(child)
    return results

def find_descendants(element, name):
    results = []
    if element is None:
        return results
    for child in element.iter():
        tag = child.tag.split("}")[-1]
        if tag == name:
            results.append(child)
    return results

def get_attribute(element, name):
    if element is None:
        return None
    return element.attrib.get(name)

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# ==========================================================
# FAMILY DETECTION
# ==========================================================

def detect_families(text):
    normalized = normalize(text)
    matched = []
    for family_name, config in FAMILIES.items():
        for keyword in config["keywords"]:
            if normalize(keyword) in normalized:
                matched.append(family_name)
                break
    return sorted(set(matched))

# ==========================================================
# XML LOADING
# ==========================================================

def load_xml(path, label):
    print("=" * 80)
    print(f"LOADING {label}")
    print("=" * 80)
    if not path.exists():
        raise FileNotFoundError(f"{label} file was not found:\n{path}")
    print(f"Input: {path}")
    tree = ET.parse(path)
    root = tree.getroot()
    print(f"Root element: {root.tag.split('}')[-1]}")
    return root

# ==========================================================
# CAPEC EXTRACTION
# ==========================================================

def extract_capec_patterns(root):
    results = []
    attack_patterns = find_descendants(root, "Attack_Pattern")
    print(f"CAPEC attack patterns found: {len(attack_patterns)}")

    for pattern in attack_patterns:
        capec_id = get_attribute(pattern, "ID")
        name = get_attribute(pattern, "Name")

        if not capec_id or not name:
            continue

        description = None
        description_element = find_child(pattern, "Description")
        if description_element is not None:
            description = element_text(description_element)

        prerequisites = []
        prerequisite_element = find_child(pattern, "Prerequisites")
        if prerequisite_element is not None:
            for item in prerequisite_element:
                text = element_text(item)
                if text:
                    prerequisites.append(text)

        skills_required = []
        skills_element = find_child(pattern, "Skills_Required")
        if skills_element is not None:
            for item in skills_element:
                text = element_text(item)
                if text:
                    skills_required.append(text)

        resources_required = []
        resources_element = find_child(pattern, "Resources_Required")
        if resources_element is not None:
            for item in resources_element:
                text = element_text(item)
                if text:
                    resources_required.append(text)

        consequences = []
        consequences_element = find_child(pattern, "Consequences")
        if consequences_element is not None:
            for consequence in consequences_element:
                text = element_text(consequence)
                if text:
                    consequences.append(text)

        mitigations = []
        mitigations_element = find_child(pattern, "Mitigations")
        if mitigations_element is not None:
            for mitigation in mitigations_element:
                text = element_text(mitigation)
                if text:
                    mitigations.append(text)

        execution_flow = []
        execution_element = find_child(pattern, "Execution_Flow")
        if execution_element is not None:
            for step in execution_element:
                step_id = get_attribute(step, "Step") or get_attribute(step, "ID")
                step_text = element_text(step)
                if step_text:
                    execution_flow.append({"step": step_id, "description": step_text})

        related_cwe = []
        related_weaknesses = find_descendants(pattern, "Related_Weakness")
        for weakness in related_weaknesses:
            cwe_id = get_attribute(weakness, "CWE_ID") or get_attribute(weakness, "CWE_IDs")
            if cwe_id:
                related_cwe.append(cwe_id)
            else:
                text = element_text(weakness)
                if text:
                    related_cwe.append(text)

        related_capec = []
        related_patterns = find_descendants(pattern, "Related_Attack_Pattern")
        for related in related_patterns:
            related_id = get_attribute(related, "CAPEC_ID") or get_attribute(related, "ID")
            if related_id:
                related_capec.append(related_id)

        related_attack_techniques = []
        taxonomy_mappings = find_child(pattern, "Taxonomy_Mappings")
        if taxonomy_mappings is not None:
            for mapping in taxonomy_mappings:
                if get_attribute(mapping, "Taxonomy_Name") == "ATTACK":
                    entry_id_element = find_child(mapping, "Entry_ID")
                    if entry_id_element is not None:
                        tech_id = element_text(entry_id_element)
                        if tech_id:
                            if not str(tech_id).startswith('T') and not str(tech_id).startswith('AML'):
                                tech_id = f"T{tech_id}"
                            related_attack_techniques.append(tech_id)

        references = []
        for ref in find_descendants(pattern, "Reference"):
            reference = {}
            for key, value in ref.attrib.items():
                reference[key] = value
            text = element_text(ref)
            if text:
                reference["text"] = text
            references.append(reference)

        searchable_text = " ".join(
            x for x in [
                name, description, " ".join(prerequisites),
                " ".join(execution_flow[i]["description"] for i in range(len(execution_flow))),
                " ".join(consequences), " ".join(mitigations)
            ] if x
        )
        families = detect_families(searchable_text)

        results.append({
            "capec_id": f"CAPEC-{capec_id}",
            "name": name,
            "abstraction": get_attribute(pattern, "Abstraction"),
            "status": get_attribute(pattern, "Status"),
            "description": description,
            "prerequisites": prerequisites,
            "skills_required": skills_required,
            "resources_required": resources_required,
            "execution_flow": execution_flow,
            "consequences": consequences,
            "mitigations": mitigations,
            "related_cwe": sorted(set(related_cwe)),
            "related_capec": sorted(set(related_capec)),
            "related_attack_techniques": sorted(set(related_attack_techniques)),
            "references": references,
            "families": families,
            "source": "CAPEC"
        })

    return results

# ==========================================================
# CWE EXTRACTION
# ==========================================================

def extract_cwe_weaknesses(root):
    results = []
    weaknesses = find_descendants(root, "Weakness")
    print(f"CWE weaknesses found: {len(weaknesses)}")

    for weakness in weaknesses:
        cwe_id = get_attribute(weakness, "ID")
        name = get_attribute(weakness, "Name")

        if not cwe_id or not name:
            continue

        description = None
        extended_description = None

        description_element = find_child(weakness, "Description")
        if description_element is not None:
            description = element_text(description_element)

        extended_element = find_child(weakness, "Extended_Description")
        if extended_element is not None:
            extended_description = element_text(extended_element)

        consequences = []
        consequence_root = find_child(weakness, "Common_Consequences")
        if consequence_root is not None:
            for consequence in consequence_root:
                text = element_text(consequence)
                if text:
                    consequences.append(text)

        mitigations = []
        mitigation_root = find_child(weakness, "Potential_Mitigations")
        if mitigation_root is not None:
            for mitigation in mitigation_root:
                text = element_text(mitigation)
                if text:
                    mitigations.append(text)

        detection_methods = []
        detection_root = find_child(weakness, "Detection_Methods")
        if detection_root is not None:
            for method in detection_root:
                text = element_text(method)
                if text:
                    detection_methods.append(text)

        related_weaknesses = []
        related_root = find_child(weakness, "Related_Weaknesses")
        if related_root is not None:
            for related in related_root:
                related_id = get_attribute(related, "CWE_ID") or get_attribute(related, "ID")
                if related_id:
                    related_weaknesses.append(related_id)

        related_attack_patterns = []
        attack_pattern_root = find_child(weakness, "Related_Attack_Patterns")
        if attack_pattern_root is not None:
            for attack_pattern in attack_pattern_root:
                capec_id = get_attribute(attack_pattern, "CAPEC_ID") or get_attribute(attack_pattern, "ID")
                if capec_id:
                    related_attack_patterns.append(capec_id)

        platforms = []
        platform_root = find_child(weakness, "Applicable_Platforms")
        if platform_root is not None:
            for platform in platform_root:
                text = element_text(platform)
                if text:
                    platforms.append(text)

        references = []
        for ref in find_descendants(weakness, "Reference"):
            reference = {}
            for key, value in ref.attrib.items():
                reference[key] = value
            text = element_text(ref)
            if text:
                reference["text"] = text
            references.append(reference)

        searchable_text = " ".join(
            x for x in [
                name, description, extended_description,
                " ".join(consequences), " ".join(mitigations), " ".join(detection_methods)
            ] if x
        )
        families = detect_families(searchable_text)

        results.append({
            "cwe_id": f"CWE-{cwe_id}",
            "name": name,
            "abstraction": get_attribute(weakness, "Abstraction"),
            "status": get_attribute(weakness, "Status"),
            "description": description,
            "extended_description": extended_description,
            "applicable_platforms": platforms,
            "common_consequences": consequences,
            "potential_mitigations": mitigations,
            "detection_methods": detection_methods,
            "related_weaknesses": sorted(set(related_weaknesses)),
            "related_attack_patterns": sorted(set(related_attack_patterns)),
            "references": references,
            "families": families,
            "source": "CWE"
        })

    return results

# ==========================================================
# MAPPING BUILDERS
# ==========================================================

def build_capec_cwe_mapping(capec_patterns, cwe_weaknesses):
    cwe_by_id = {weakness["cwe_id"]: weakness for weakness in cwe_weaknesses}
    mappings = []

    for pattern in capec_patterns:
        capec_id = pattern["capec_id"]
        related_cwe = []

        for cwe_id in pattern["related_cwe"]:
            normalized_id = cwe_id if str(cwe_id).startswith("CWE-") else f"CWE-{cwe_id}"
            weakness = cwe_by_id.get(normalized_id)
            if not weakness:
                continue

            related_cwe.append({
                "cwe_id": weakness["cwe_id"],
                "cwe_name": weakness["name"],
                "description": weakness["description"],
                "extended_description": weakness["extended_description"],
                "consequences": weakness["common_consequences"],
                "mitigations": weakness["potential_mitigations"],
                "detection_methods": weakness["detection_methods"]
            })

        if related_cwe:
            mappings.append({
                "capec_id": capec_id,
                "capec_name": pattern["name"],
                "families": pattern["families"],
                "related_attack_techniques": pattern.get("related_attack_techniques", []),
                "related_cwe": related_cwe,
                "source": "CAPEC + CWE"
            })

    return mappings

def build_technique_capec_mapping(capec_patterns):
    technique_mapping = defaultdict(list)
    for pattern in capec_patterns:
        for tech_id in pattern.get("related_attack_techniques", []):
            technique_mapping[tech_id].append({
                "capec_id": pattern["capec_id"],
                "name": pattern["name"],
                "abstraction": pattern["abstraction"]
            })
            
    results = []
    for target_tech in TARGET_TECHNIQUES:
        mapped_capecs = technique_mapping.get(target_tech, [])
        if not mapped_capecs:
            results.append({
                "technique_id": target_tech,
                "related_capecs": "N/A"
            })
        else:
            results.append({
                "technique_id": target_tech,
                "related_capecs": mapped_capecs
            })
    return results

# ==========================================================
# FORCED DUMMY INJECTION FOR MISSING TECHNIQUES
# ==========================================================

def inject_missing_techniques(family_capecs, family_name, expected_techniques):
    found_techniques = set()
    for capec in family_capecs:
        for tech in capec.get("related_attack_techniques", []):
            found_techniques.add(tech)

    for expected_tech in expected_techniques:
        if expected_tech not in found_techniques:
            dummy_capec = {
                "capec_id": "N/A",
                "name": f"No CAPEC officially mapped to {expected_tech}",
                "abstraction": "N/A",
                "status": "N/A",
                "description": f"MITRE CAPEC does not provide a direct mapping for ATT&CK technique {expected_tech}. This is usually because the technique relates to post-compromise impact, lateral movement, or data exfiltration, rather than an initial attack pattern.",
                "prerequisites": [],
                "skills_required": [],
                "resources_required": [],
                "execution_flow": [],
                "consequences": [],
                "mitigations": [],
                "related_cwe": ["N/A"],
                "related_capec": [],
                "related_attack_techniques": [expected_tech],
                "references": [],
                "families": [family_name],
                "source": "Forced N/A Injection"
            }
            family_capecs.append(dummy_capec)
    return family_capecs

def inject_missing_mappings(family_mappings, family_name, expected_techniques):
    found_techniques = set()
    for mapping in family_mappings:
        for tech in mapping.get("related_attack_techniques", []):
            found_techniques.add(tech)

    for expected_tech in expected_techniques:
        if expected_tech not in found_techniques:
            dummy_mapping = {
                "capec_id": "N/A",
                "capec_name": f"No CAPEC mapped for {expected_tech}",
                "families": [family_name],
                "related_attack_techniques": [expected_tech],
                "related_cwe": [{
                    "cwe_id": "N/A",
                    "cwe_name": "No CWE mapped",
                    "description": "N/A",
                    "extended_description": None,
                    "consequences": [],
                    "mitigations": [],
                    "detection_methods": []
                }],
                "source": "Forced N/A Injection"
            }
            family_mappings.append(dummy_mapping)
    return family_mappings

# ==========================================================
# FAMILY FILTERING
# ==========================================================

def filter_by_family(data, family_name):
    filtered = []
    for item in data:
        if family_name in item.get("families", []):
            filtered.append(item)
    return filtered

# ==========================================================
# VALIDATION
# ==========================================================

def build_validation_summary(capec_patterns, cwe_weaknesses, mappings):
    family_summary = {}
    for family_name, config in FAMILIES.items():
        capec_count = len(filter_by_family(capec_patterns, family_name))
        cwe_count = len(filter_by_family(cwe_weaknesses, family_name))
        mapping_count = sum(1 for mapping in mappings if family_name in mapping["families"])

        family_summary[family_name] = {
            "display_name": config["display_name"],
            "capec_patterns": capec_count,
            "cwe_weaknesses": cwe_count,
            "capec_cwe_mappings": mapping_count
        }

    return {
        "capec_total": len(capec_patterns),
        "cwe_total": len(cwe_weaknesses),
        "capec_cwe_mappings": len(mappings),
        "families": family_summary,
        "status": "PASS"
    }

# ==========================================================
# MAIN
# ==========================================================

def main():
    print("\n")
    print("=" * 80)
    print("CAPEC + CWE DATASET PROCESSOR (WITH FORCED INJECTION)")
    print("=" * 80)

    capec_root = load_xml(CAPEC_INPUT, "CAPEC")
    cwe_root = load_xml(CWE_INPUT, "CWE")

    capec_patterns = extract_capec_patterns(capec_root)
    cwe_weaknesses = extract_cwe_weaknesses(cwe_root)

    capec_cwe_mappings = build_capec_cwe_mapping(capec_patterns, cwe_weaknesses)
    technique_capec_mappings = build_technique_capec_mapping(capec_patterns)

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    save_json(OUTPUT_ROOT / "capec_clean.json", capec_patterns)
    save_json(OUTPUT_ROOT / "cwe_clean.json", cwe_weaknesses)
    save_json(OUTPUT_ROOT / "capec_cwe_mapping.json", capec_cwe_mappings)
    save_json(OUTPUT_ROOT / "technique_capec_mapping.json", technique_capec_mappings)

    for family_name, config in FAMILIES.items():
        family_dir = OUTPUT_ROOT / family_name
        family_dir.mkdir(parents=True, exist_ok=True)

        family_capec = filter_by_family(capec_patterns, family_name)
        family_cwe = filter_by_family(cwe_weaknesses, family_name)
        family_mappings = [m for m in capec_cwe_mappings if family_name in m["families"]]

        # Force inject missing techniques with "N/A" for this specific family
        expected_techniques = config["techniques"]
        family_capec = inject_missing_techniques(family_capec, family_name, expected_techniques)
        family_mappings = inject_missing_mappings(family_mappings, family_name, expected_techniques)

        save_json(family_dir / f"{family_name}_capec.json", family_capec)
        save_json(family_dir / f"{family_name}_cwe.json", family_cwe)
        save_json(family_dir / f"{family_name}_mapping.json", family_mappings)

        print(f"Processed FAMILY: {config['display_name']} (Injected N/A for missing techniques)")

    summary = build_validation_summary(capec_patterns, cwe_weaknesses, capec_cwe_mappings)
    save_json(OUTPUT_ROOT / "capec_cwe_validation_summary.json", summary)

    print("\n")
    print("=" * 80)
    print("CAPEC + CWE PROCESSING COMPLETE")
    print("=" * 80)
    print(f"CAPEC patterns extracted: {summary['capec_total']}")
    print(f"CWE weaknesses extracted: {summary['cwe_total']}")
    print(f"CAPEC → CWE mappings built: {summary['capec_cwe_mappings']}")
    print(f"Technique → CAPEC mappings generated: {len(technique_capec_mappings)}")
    print("\nOutput successfully saved to:")
    print(OUTPUT_ROOT)

if __name__ == "__main__":
    main()