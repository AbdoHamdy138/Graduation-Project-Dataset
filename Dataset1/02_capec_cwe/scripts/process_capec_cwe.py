import xml.etree.ElementTree as ET
import json
import os

CAPEC_XML = r"E:\Graduation Project\Dataset1\CAPEC\capec.xml"
CWE_XML = r"E:\Graduation Project\Dataset1\CWE\cwe.xml"
OUTPUT_DIR = r"E:\Graduation Project\Dataset1\02_capec_cwe"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def sanitize(data):
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            val = sanitize(v)
            if val in ([], {}, "", None):
                sanitized[k] = "N/A"
            else:
                sanitized[k] = val
        return sanitized
    elif isinstance(data, list):
        if not data:
            return "N/A"
        sanitized = [sanitize(item) for item in data]
        return sanitized
    else:
        if data in ("", None):
            return "N/A"
        return data

def get_text(element):
    if element is None:
        return ""
    texts = [t.strip() for t in element.itertext() if t.strip()]
    return " ".join(texts)

def parse_capec():
    tree = ET.parse(CAPEC_XML)
    root = tree.getroot()
    ns = {'capec': 'http://capec.mitre.org/capec-3'}
    
    ext_refs = {}
    for ext_ref in root.findall('.//capec:External_References/capec:External_Reference', ns):
        ref_id = ext_ref.attrib.get('Reference_ID')
        title = get_text(ext_ref.find('capec:Title', ns))
        url_el = ext_ref.find('capec:URL', ns)
        url = get_text(url_el) if url_el is not None else ""
        ext_refs[ref_id] = {'Title': title, 'URL': url}

    capec_list = []
    technique_capec_mapping = []
    capec_cwe_mapping = []

    for ap in root.findall('.//capec:Attack_Patterns/capec:Attack_Pattern', ns):
        capec_id = ap.attrib.get('ID')
        name = ap.attrib.get('Name')
        abstraction = ap.attrib.get('Abstraction')
        
        desc = get_text(ap.find('capec:Description', ns))
        ext_desc = get_text(ap.find('capec:Extended_Description', ns))
        full_desc = f"{desc} {ext_desc}".strip()
        
        prereqs = []
        for prereq in ap.findall('.//capec:Prerequisites/capec:Prerequisite', ns):
            prereqs.append(get_text(prereq))
            
        execution_flow = []
        for step in ap.findall('.//capec:Execution_Flow/capec:Attack_Step', ns):
            step_num = get_text(step.find('capec:Step', ns))
            phase = get_text(step.find('capec:Phase', ns))
            s_desc = get_text(step.find('capec:Description', ns))
            techs = [get_text(t) for t in step.findall('capec:Technique', ns)]
            execution_flow.append({
                'Step': step_num,
                'Phase': phase,
                'Description': s_desc,
                'Techniques': techs
            })
            
        attack_mappings = []
        for mapping in ap.findall('.//capec:Taxonomy_Mappings/capec:Taxonomy_Mapping', ns):
            if mapping.attrib.get('Taxonomy_Name') == 'ATTACK':
                entry_id = get_text(mapping.find('capec:Entry_ID', ns))
                entry_name = get_text(mapping.find('capec:Entry_Name', ns))
                attack_mappings.append({'Entry_ID': entry_id, 'Entry_Name': entry_name})
                if entry_id:
                    technique_capec_mapping.append({'Technique_ID': entry_id, 'CAPEC_ID': capec_id})
                
        cwes = []
        for rw in ap.findall('.//capec:Related_Weaknesses/capec:Related_Weakness', ns):
            cwe_id = rw.attrib.get('CWE_ID')
            if cwe_id:
                cwes.append(cwe_id)
                capec_cwe_mapping.append({'CAPEC_ID': capec_id, 'CWE_ID': cwe_id})
                
        consequences = []
        for cons in ap.findall('.//capec:Consequences/capec:Consequence', ns):
            scopes = [get_text(s) for s in cons.findall('capec:Scope', ns)]
            impacts = [get_text(i) for i in cons.findall('capec:Impact', ns)]
            note = get_text(cons.find('capec:Note', ns))
            consequences.append({'Scope': scopes, 'Impact': impacts, 'Note': note})
            
        mitigations = []
        for mit in ap.findall('.//capec:Mitigations/capec:Mitigation', ns):
            mitigations.append(get_text(mit))
            
        references = []
        for ref in ap.findall('.//capec:References/capec:Reference', ns):
            ref_id = ref.attrib.get('External_Reference_ID')
            if ref_id in ext_refs:
                references.append(ext_refs[ref_id])
            else:
                references.append({'Reference_ID': ref_id})
                
        capec_list.append({
            'CAPEC_ID': capec_id,
            'Name': name,
            'Description': full_desc,
            'Abstraction': abstraction,
            'Prerequisites': prereqs,
            'Execution_Flow': execution_flow,
            'Related_ATTACK': attack_mappings,
            'Related_CWEs': cwes,
            'Consequences': consequences,
            'Mitigations': mitigations,
            'References': references,
            'Source_URL': f"https://capec.mitre.org/data/definitions/{capec_id}.html"
        })
        
    return capec_list, technique_capec_mapping, capec_cwe_mapping

def parse_cwe(capec_cwe_mapping):
    tree = ET.parse(CWE_XML)
    root = tree.getroot()
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    
    ext_refs = {}
    for ext_ref in root.findall('.//cwe:External_References/cwe:External_Reference', ns):
        ref_id = ext_ref.attrib.get('Reference_ID')
        title = get_text(ext_ref.find('cwe:Title', ns))
        url_el = ext_ref.find('cwe:URL', ns)
        url = get_text(url_el) if url_el is not None else ""
        ext_refs[ref_id] = {'Title': title, 'URL': url}

    cwe_to_capec = {}
    for mapping in capec_cwe_mapping:
        cwe_id = mapping['CWE_ID']
        capec_id = mapping['CAPEC_ID']
        if cwe_id not in cwe_to_capec:
            cwe_to_capec[cwe_id] = []
        cwe_to_capec[cwe_id].append(capec_id)

    cwe_list = []
    
    for weakness in root.findall('.//cwe:Weaknesses/cwe:Weakness', ns):
        cwe_id = weakness.attrib.get('ID')
        name = weakness.attrib.get('Name')
        abstraction = weakness.attrib.get('Abstraction')
        
        desc = get_text(weakness.find('cwe:Description', ns))
        ext_desc = get_text(weakness.find('cwe:Extended_Description', ns))
        full_desc = f"{desc} {ext_desc}".strip()
        
        related_capecs = cwe_to_capec.get(cwe_id, [])
        for rap in weakness.findall('.//cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern', ns):
            cap_id = rap.attrib.get('CAPEC_ID')
            if cap_id and cap_id not in related_capecs:
                related_capecs.append(cap_id)
        
        consequences = []
        for cons in weakness.findall('.//cwe:Common_Consequences/cwe:Consequence', ns):
            scopes = [get_text(s) for s in cons.findall('cwe:Scope', ns)]
            impacts = [get_text(i) for i in cons.findall('cwe:Impact', ns)]
            note = get_text(cons.find('cwe:Note', ns))
            consequences.append({'Scope': scopes, 'Impact': impacts, 'Note': note})
            
        detection_methods = []
        for dm in weakness.findall('.//cwe:Detection_Methods/cwe:Detection_Method', ns):
            method = get_text(dm.find('cwe:Method', ns))
            desc_dm = get_text(dm.find('cwe:Description', ns))
            eff = get_text(dm.find('cwe:Effectiveness', ns))
            eff_notes = get_text(dm.find('cwe:Effectiveness_Notes', ns))
            detection_methods.append({'Method': method, 'Description': desc_dm, 'Effectiveness': eff, 'Effectiveness_Notes': eff_notes})
            
        mitigations = []
        for mit in weakness.findall('.//cwe:Potential_Mitigations/cwe:Mitigation', ns):
            phase = [get_text(p) for p in mit.findall('cwe:Phase', ns)]
            m_desc = get_text(mit.find('cwe:Description', ns))
            eff = get_text(mit.find('cwe:Effectiveness', ns))
            eff_notes = get_text(mit.find('cwe:Effectiveness_Notes', ns))
            mitigations.append({'Phase': phase, 'Description': m_desc, 'Effectiveness': eff, 'Effectiveness_Notes': eff_notes})
            
        platforms = []
        for plat in weakness.findall('.//cwe:Applicable_Platforms/cwe:Language', ns):
            platforms.append({'Type': 'Language', 'Name': plat.attrib.get('Name'), 'Class': plat.attrib.get('Class'), 'Prevalence': plat.attrib.get('Prevalence')})
        for plat in weakness.findall('.//cwe:Applicable_Platforms/cwe:Technology', ns):
            platforms.append({'Type': 'Technology', 'Name': plat.attrib.get('Name'), 'Class': plat.attrib.get('Class'), 'Prevalence': plat.attrib.get('Prevalence')})
        for plat in weakness.findall('.//cwe:Applicable_Platforms/cwe:Operating_System', ns):
            platforms.append({'Type': 'Operating_System', 'Name': plat.attrib.get('Name'), 'Class': plat.attrib.get('Class'), 'Prevalence': plat.attrib.get('Prevalence')})
        for plat in weakness.findall('.//cwe:Applicable_Platforms/cwe:Architecture', ns):
            platforms.append({'Type': 'Architecture', 'Name': plat.attrib.get('Name'), 'Class': plat.attrib.get('Class'), 'Prevalence': plat.attrib.get('Prevalence')})
            
        references = []
        for ref in weakness.findall('.//cwe:References/cwe:Reference', ns):
            ref_id = ref.attrib.get('External_Reference_ID')
            if ref_id in ext_refs:
                references.append(ext_refs[ref_id])
            else:
                references.append({'Reference_ID': ref_id})
                
        cwe_list.append({
            'CWE_ID': cwe_id,
            'Name': name,
            'Description': full_desc,
            'Weakness_Type_Abstraction': abstraction,
            'Related_CAPEC': list(set(related_capecs)),
            'Consequences': consequences,
            'Detection_Methods': detection_methods,
            'Potential_Mitigations': mitigations,
            'Applicable_Platforms_Technologies': platforms,
            'References': references,
            'Source_URL': f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        })
        
    return cwe_list

def main():
    print("Parsing CAPEC...")
    capec_list, technique_capec_mapping, capec_cwe_mapping = parse_capec()
    print("Parsing CWE...")
    cwe_list = parse_cwe(capec_cwe_mapping)
    
    # Sanitize lists
    capec_list = sanitize(capec_list)
    cwe_list = sanitize(cwe_list)
    
    technique_capec_mapping = sanitize(technique_capec_mapping)
    capec_cwe_mapping = sanitize(capec_cwe_mapping)
    
    # For mappings, maybe also sanitize, though they shouldn't have empty nested objects
    if technique_capec_mapping == "N/A": technique_capec_mapping = []
    if capec_cwe_mapping == "N/A": capec_cwe_mapping = []
    
    print("Writing capec_clean.json...")
    with open(os.path.join(OUTPUT_DIR, 'capec_clean.json'), 'w', encoding='utf-8') as f:
        json.dump(capec_list, f, indent=4)
        
    print("Writing cwe_clean.json...")
    with open(os.path.join(OUTPUT_DIR, 'cwe_clean.json'), 'w', encoding='utf-8') as f:
        json.dump(cwe_list, f, indent=4)
        
    print("Writing technique_capec_mapping.json...")
    with open(os.path.join(OUTPUT_DIR, 'technique_capec_mapping.json'), 'w', encoding='utf-8') as f:
        json.dump(technique_capec_mapping, f, indent=4)
        
    print("Writing capec_cwe_mapping.json...")
    with open(os.path.join(OUTPUT_DIR, 'capec_cwe_mapping.json'), 'w', encoding='utf-8') as f:
        json.dump(capec_cwe_mapping, f, indent=4)
        
    print("Done!")

if __name__ == "__main__":
    main()
