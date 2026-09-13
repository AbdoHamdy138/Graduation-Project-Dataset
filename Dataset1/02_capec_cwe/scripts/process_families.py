import os
import json
import urllib.request

DATA_DIR = r"E:\Graduation Project\Dataset1\02_capec_cwe"
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")

os.makedirs(PROCESSED_DIR, exist_ok=True)

# Define families
FAMILIES = {
    "malware_backdoor": {
        "techniques": ["T1018", "T1069", "T1087", "T1482", "T1053", "T1059", "T1543", "T1547", "T1027", "T1055", "T1070", "T1105"],
        "cwes": [],
        "capecs": []
    },
    "social_engineering_credential_theft": {
        "techniques": ["T1566", "T1003", "T1552", "T1555", "T1558"],
        "cwes": [],
        "capecs": []
    },
    "ransomware_data_impact": {
        "techniques": ["T1021", "T1041", "T1048", "T1570", "T1486"],
        "cwes": [],
        "capecs": []
    },
    "web_injection": {
        "techniques": ["AML.T0051"],
        "cwes": ["89", "79", "77"],
        "capecs": ["66", "88"]
    },
    "authentication_bruteforce": {
        "techniques": ["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004", "T1078"],
        "cwes": [],
        "capecs": []
    },
    "dos_ddos_botnet_c2": {
        "techniques": ["T1498", "T1499", "T1071"],
        "cwes": [],
        "capecs": []
    }
}

def load_attack_data():
    url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    print("Fetching ATT&CK data...")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
        
        attack_map = {}
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                ext_refs = obj.get('external_references', [])
                tech_id = None
                for ref in ext_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        tech_id = ref.get('external_id')
                        break
                if tech_id:
                    attack_map[tech_id] = {
                        "Description": obj.get('description', 'N/A'),
                        "Name": obj.get('name', 'N/A'),
                        "Source_URL": ext_refs[0].get('url', 'N/A') if ext_refs else 'N/A',
                        "Mitigations": [] # Will need course-of-action for this if wanted strictly, but description suffices for now.
                    }
        return attack_map
    except Exception as e:
        print(f"Failed to fetch ATT&CK data: {e}")
        return {}

def main():
    attack_data = load_attack_data()
    
    with open(os.path.join(DATA_DIR, 'capec_clean.json'), 'r', encoding='utf-8') as f:
        capec_list = json.load(f)
        
    with open(os.path.join(DATA_DIR, 'cwe_clean.json'), 'r', encoding='utf-8') as f:
        cwe_list = json.load(f)
        
    capec_lookup = {c['CAPEC_ID']: c for c in capec_list}
    cwe_lookup = {c['CWE_ID']: c for c in cwe_list}
    
    tech_to_capecs = {}
    for c in capec_list:
        if isinstance(c.get('Related_ATTACK'), list):
            for rel in c['Related_ATTACK']:
                tid = rel.get('Entry_ID')
                if tid:
                    tech_to_capecs.setdefault(tid, []).append(c['CAPEC_ID'])
                    
    for family, rules in FAMILIES.items():
        family_dir = os.path.join(PROCESSED_DIR, family)
        os.makedirs(family_dir, exist_ok=True)
        
        collected_capecs = set(rules['capecs'])
        collected_cwes = set(rules['cwes'])
        collected_techs = set(rules['techniques'])
        
        for tid in collected_techs:
            if tid in tech_to_capecs:
                collected_capecs.update(tech_to_capecs[tid])
                
        for cid in collected_capecs:
            if cid in capec_lookup:
                cwes = capec_lookup[cid].get('Related_CWEs', [])
                if isinstance(cwes, list):
                    collected_cwes.update(cwes)
                    
        out_cwe = []
        for cwe_id in collected_cwes:
            if cwe_id in cwe_lookup:
                out_cwe.append(cwe_lookup[cwe_id])
                
        with open(os.path.join(family_dir, f'{family}_cwe.json'), 'w', encoding='utf-8') as f:
            json.dump(out_cwe, f, indent=4)
            
        out_capec = []
        for cid in collected_capecs:
            if cid in capec_lookup:
                out_capec.append(capec_lookup[cid])
                
        for tid in collected_techs:
            if tid not in tech_to_capecs:
                info = attack_data.get(tid, {})
                out_capec.append({
                    "CAPEC_ID": f"N/A ({tid})",
                    "Name": info.get("Name", f"Unknown Technique {tid}"),
                    "Description": info.get("Description", "No description available."),
                    "Source_URL": info.get("Source_URL", "N/A"),
                    "Related_ATTACK": [{"Entry_ID": tid, "Entry_Name": info.get("Name", "N/A")}],
                    "source": "ATTACK API",
                    "Abstraction": "N/A",
                    "Prerequisites": "N/A",
                    "Execution_Flow": "N/A",
                    "Consequences": "N/A",
                    "Mitigations": "N/A",
                    "References": "N/A"
                })
                
        with open(os.path.join(family_dir, f'{family}_capec.json'), 'w', encoding='utf-8') as f:
            json.dump(out_capec, f, indent=4)
            
        mapping = {
            "family": family,
            "techniques": list(collected_techs),
            "capecs": list(collected_capecs),
            "cwes": list(collected_cwes)
        }
        with open(os.path.join(family_dir, f'{family}_mapping.json'), 'w', encoding='utf-8') as f:
            json.dump(mapping, f, indent=4)
            
    print("Families processed.")

if __name__ == "__main__":
    main()
