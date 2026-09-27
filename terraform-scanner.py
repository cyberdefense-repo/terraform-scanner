import json
import os
import hcl2

def parse_hcl_file(file_path):
    with open(file_path, 'r') as f:
        return hcl2.load(f)

def analyze_policy_statement(statement):
    findings = []
    actions = statement.get('Action', [])
    resources = statement.get('Resource', [])
    effect = statement.get('Effect', 'Allow')

    if effect == 'Allow':
        if '*' in actions or ['*'] == actions:
            findings.append("High Risk: Wildcard '*' used in Action grants full administrative permissions.")
        if '*' in resources or ['*'] == resources:
            findings.append("Medium Risk: Wildcard '*' used in Resource allows access across all resources.")
            
    return findings

def scan_terraform_file(file_path):
    print(f"Scanning file: {file_path}")
    parsed_data = parse_hcl_file(file_path)
    all_findings = {}

    # Extract resource blocks from HCL
    for resource in parsed_data.get('resource', []):
        for res_type, res_content in resource.items():
            if res_type == 'aws_iam_policy':
                for policy_name, policy_body in res_content.items():
                    # Parse the inline JSON policy string
                    policy_json_str = policy_body.get('policy', [''])[0]
                    try:
                        policy_dict = json.loads(policy_json_str)
                        statements = policy_dict.get('Statement', [])
                        if isinstance(statements, dict):
                            statements = [statements]
                            
                        file_findings = []
                        for stmt in statements:
                            file_findings.extend(analyze_policy_statement(stmt))
                            
                        if file_findings:
                            all_findings[policy_name] = file_findings
                    except json.JSONDecodeError:
                        all_findings[policy_name] = ["Error: Could not parse policy JSON string."]
                        
    return all_findings

if __name__ == "__main__":
    target_file = "example_iam.tf"
    if os.path.exists(target_file):
        results = scan_terraform_file(target_file)
        print(json.dumps(results, indent=2))
    else:
        print(f"Target file {target_file} not found. Create a sample Terraform file to test.")

