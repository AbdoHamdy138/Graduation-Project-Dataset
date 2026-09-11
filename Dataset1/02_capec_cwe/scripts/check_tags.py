import xml.etree.ElementTree as ET

CAPEC_XML = r"E:\Graduation Project\Dataset1\CAPEC\capec.xml"
CWE_XML = r"E:\Graduation Project\Dataset1\CWE\cwe.xml"

def get_child_tags(file_path, parent_tag, ns):
    tree = ET.parse(file_path)
    root = tree.getroot()
    tags = set()
    for item in root.findall(f'.//{ns}:{parent_tag}', {'ns': ns.split('}')[0].strip('{')}):
        for child in item:
            # strip namespace
            tag = child.tag.split('}')[-1]
            tags.add(tag)
    return tags

print("Checking CAPEC...")
try:
    tree = ET.parse(CAPEC_XML)
    root = tree.getroot()
    ns = {'capec': 'http://capec.mitre.org/capec-3'}
    capec_tags = set()
    for ap in root.findall('.//capec:Attack_Patterns/capec:Attack_Pattern', ns):
        for child in ap:
            capec_tags.add(child.tag.split('}')[-1])
    print("CAPEC top-level tags present in XML:")
    for tag in sorted(capec_tags):
        print(f" - {tag}")
except Exception as e:
    print(f"Error reading CAPEC: {e}")

print("\nChecking CWE...")
try:
    tree = ET.parse(CWE_XML)
    root = tree.getroot()
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    cwe_tags = set()
    for weakness in root.findall('.//cwe:Weaknesses/cwe:Weakness', ns):
        for child in weakness:
            cwe_tags.add(child.tag.split('}')[-1])
    print("CWE top-level tags present in XML:")
    for tag in sorted(cwe_tags):
        print(f" - {tag}")
except Exception as e:
    print(f"Error reading CWE: {e}")
