import csv
import json
from datetime import datetime
import ast
import argparse
import os

def process_mitre_data(csv_path):
    # Validate file exists
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
    # Initialize counters
    tactics_count = {}
    techniques_count = {}
    rules_with_mappings = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8-sig') as f:  # Handle BOM if present
            # First peek at file to check format
            first_line = f.readline().strip()
            f.seek(0)  # Reset to start
            
            # Print diagnostic info
            print(f"First line of CSV: {first_line}")
            
            reader = csv.reader(f)
            headers = [h.strip() for h in next(reader)]  # Strip whitespace
            
            # Check required columns exist
            required_columns = ['Title', 'MITRE Mapping']
            missing_columns = [col for col in required_columns if col not in headers]
            
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}\nFound columns: {headers}")
                
            title_idx = headers.index('Title')
            mapping_idx = headers.index('MITRE Mapping')
            
            for row in reader:
                if len(row) >= max(title_idx + 1, mapping_idx + 1):
                    rule_name = row[title_idx].strip()
                    mitre_mapping = row[mapping_idx].strip()
                    
                    if mitre_mapping:
                        try:
                            # Clean up the MITRE mapping string format
                            mitre_mapping = mitre_mapping.replace(' ', '')
                            techniques = ast.literal_eval(mitre_mapping)
                            
                            if techniques:  # Only process non-empty arrays
                                rules_with_mappings.append({
                                    'name': rule_name,
                                    'techniques': techniques
                                })
                                
                                # Count techniques
                                for technique in techniques:
                                    technique = technique.strip()
                                    if technique:  # Skip empty strings
                                        techniques_count[technique] = techniques_count.get(technique, 0) + 1
                                        
                                        # Extract tactic from technique
                                        if '.' in technique:
                                            base_technique = technique.split('.')[0]
                                            tactics_count[base_technique] = tactics_count.get(base_technique, 0) + 1
                                        else:
                                            tactics_count[technique] = tactics_count.get(technique, 0) + 1
                                    
                        except (ValueError, SyntaxError) as e:
                            print(f"Error parsing MITRE mapping for rule {rule_name}: {e}")
                            continue

        # Rest of the code remains the same
        max_score = max(techniques_count.values()) if techniques_count else 1
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        layer_filename = f"layer_splunk_{current_time}.json"

        layer_json = {
            "name": "Splunk Rules MITRE Coverage",
            "versions": {
                "attack": "16",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"Coverage of {len(techniques_count)} MITRE ATT&CK techniques in Splunk rules",
            "metadata": [
                {
                    "name": "generated",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                {
                    "name": "rules_analyzed", 
                    "value": str(len(rules_with_mappings))
                }
            ],
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": count,
                    "color": f"#{min(255, count * 50):02x}3333",
                    "enabled": True,
                    "metadata": [
                        {
                            "name": "Rules Using Technique",
                            "value": "\n".join([
                                rule['name'] for rule in rules_with_mappings 
                                if tid in rule['techniques']
                            ])
                        }
                    ],
                    "showSubtechniques": True
                } for tid, count in techniques_count.items()
            ],
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": max_score
            }
        }
        
        with open(layer_filename, 'w') as f:
            json.dump(layer_json, f, indent=2)
            
        print("\n=== MITRE Coverage Statistics ===")
        print(f"\nTotal Coverage:")
        print(f"- Rules with MITRE mappings: {len(rules_with_mappings)}")
        print(f"- Unique techniques covered: {len(techniques_count)}")
        print(f"- Unique tactics covered: {len(tactics_count)}")
        
        technique_stats = dict(sorted(techniques_count.items(), key=lambda x: x[1], reverse=True))
        print("\nTop 5 techniques by implementation:")
        for technique, count in list(technique_stats.items())[:5]:
            print(f"  • {technique}: {count} rules")
            
        print(f"\nLayer file saved as: {layer_filename}")
        print("You can visualize this layer at: https://mitre-attack.github.io/attack-navigator/")
        
    except Exception as e:
        print(f"Error processing MITRE data: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Generate MITRE ATT&CK Navigator layer from CSV mapping file',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-f', '--file',
        default='SplunkRules.csv',  # Updated default filename
        help='Path to CSV file containing MITRE mappings'
    )
    
    args = parser.parse_args()
    
    try:
        process_mitre_data(args.file)
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())