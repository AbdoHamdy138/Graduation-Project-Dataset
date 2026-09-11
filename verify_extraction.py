import xml.etree.ElementTree as ET
import json
import os

CAPEC_XML = r"E:\Graduation Project\Dataset1\CAPEC\capec.xml"
CWE_XML = r"E:\Graduation Project\Dataset1\CWE\cwe.xml"
CAPEC_JSON = r"E:\Graduation Project\Dataset1\02_capec_cwe\capec_clean.json"
CWE_JSON = r"E:\Graduation Project\Dataset1\02_capec_cwe\cwe_clean.json"

def verify_capec():
    print("--- Verifying CAPEC ---")
    tree = ET.parse(CAPEC_XML)
    root = tree.getroot()
    ns = {'capec': 'http://capec.mitre.org/capec-3'}
    
    xml_patterns = {ap.attrib.get('ID'): ap for ap in root.findall('.//capec:Attack_Patterns/capec:Attack_Pattern', ns)}
    
    with open(CAPEC_JSON, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
        
    print(f"Total CAPEC entries in XML: {len(xml_patterns)}")
    print(f"Total CAPEC entries in JSON: {len(json_data)}")
    if len(xml_patterns) != len(json_data):
        print("WARNING: Entry count mismatch!")
        
    errors = 0
    for entry in json_data:
        c_id = entry['CAPEC_ID']
        ap = xml_patterns[c_id]
        
        # Prerequisites
        has_prereq = len(ap.findall('.//capec:Prerequisites/capec:Prerequisite', ns)) > 0
        if has_prereq and entry['Prerequisites'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Prerequisites in XML but N/A in JSON")
            errors += 1
            
        # Execution Flow
        has_flow = len(ap.findall('.//capec:Execution_Flow/capec:Attack_Step', ns)) > 0
        if has_flow and entry['Execution_Flow'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Execution_Flow in XML but N/A in JSON")
            errors += 1
            
        # Related ATTACK
        has_attack = False
        for mapping in ap.findall('.//capec:Taxonomy_Mappings/capec:Taxonomy_Mapping', ns):
            if mapping.attrib.get('Taxonomy_Name') == 'ATTACK':
                has_attack = True
                break
        if has_attack and entry['Related_ATTACK'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Related_ATTACK in XML but N/A in JSON")
            errors += 1
            
        # Related CWEs
        has_cwes = len(ap.findall('.//capec:Related_Weaknesses/capec:Related_Weakness', ns)) > 0
        if has_cwes and entry['Related_CWEs'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Related_CWEs in XML but N/A in JSON")
            errors += 1
            
        # Consequences
        has_cons = len(ap.findall('.//capec:Consequences/capec:Consequence', ns)) > 0
        if has_cons and entry['Consequences'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Consequences in XML but N/A in JSON")
            errors += 1
            
        # Mitigations
        has_mit = len(ap.findall('.//capec:Mitigations/capec:Mitigation', ns)) > 0
        if has_mit and entry['Mitigations'] == "N/A":
            print(f"Error CAPEC {c_id}: Has Mitigations in XML but N/A in JSON")
            errors += 1
            
    print(f"CAPEC Verification complete. Errors found: {errors}")

def verify_cwe():
    print("\n--- Verifying CWE ---")
    tree = ET.parse(CWE_XML)
    root = tree.getroot()
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    
    xml_weaknesses = {w.attrib.get('ID'): w for w in root.findall('.//cwe:Weaknesses/cwe:Weakness', ns)}
    
    with open(CWE_JSON, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
        
    print(f"Total CWE entries in XML: {len(xml_weaknesses)}")
    print(f"Total CWE entries in JSON: {len(json_data)}")
    if len(xml_weaknesses) != len(json_data):
        print("WARNING: Entry count mismatch!")
        
    errors = 0
    for entry in json_data:
        w_id = entry['CWE_ID']
        w = xml_weaknesses[w_id]
        
        # Consequences
        has_cons = len(w.findall('.//cwe:Common_Consequences/cwe:Consequence', ns)) > 0
        if has_cons and entry['Consequences'] == "N/A":
            print(f"Error CWE {w_id}: Has Consequences in XML but N/A in JSON")
            errors += 1
            
        # Detection Methods
        has_dm = len(w.findall('.//cwe:Detection_Methods/cwe:Detection_Method', ns)) > 0
        if has_dm and entry['Detection_Methods'] == "N/A":
            print(f"Error CWE {w_id}: Has Detection_Methods in XML but N/A in JSON")
            errors += 1
            
        # Mitigations
        has_mit = len(w.findall('.//cwe:Potential_Mitigations/cwe:Mitigation', ns)) > 0
        if has_mit and entry['Potential_Mitigations'] == "N/A":
            print(f"Error CWE {w_id}: Has Potential_Mitigations in XML but N/A in JSON")
            errors += 1
            
        # Applicable Platforms
        has_plat = len(w.findall('.//cwe:Applicable_Platforms/*', ns)) > 0
        if has_plat and entry['Applicable_Platforms_Technologies'] == "N/A":
            print(f"Error CWE {w_id}: Has Platforms in XML but N/A in JSON")
            errors += 1
            
    print(f"CWE Verification complete. Errors found: {errors}")

if __name__ == '__main__':
    verify_capec()
    verify_cwe()
