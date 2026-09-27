import boto3
import os
from dotenv import load_dotenv

load_dotenv()
dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION'))
table = dynamodb.Table(os.getenv('DYNAMO_TABLE_NAME'))

total = 0
has_flags = 0
has_flags_and_valid_asn = 0

response = table.scan(Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='ip, search_results.behavioral_flags, search_results.bgp_info')
items = response.get('Items', [])
while True:
    for item in items:
        ip = item.get('ip', '')
        if ip.startswith('__'): continue
        total += 1
        sr = item.get('search_results', {})
        flags = sr.get('behavioral_flags')
        bgp = sr.get('bgp_info', {})
        asn = bgp.get('asn', '') if isinstance(bgp, dict) else ''

        if flags and len(flags) > 0:
            has_flags += 1
            if asn and asn not in ("Unknown", "BGP Lookup Unavailable"):
                has_flags_and_valid_asn += 1
    
    if 'LastEvaluatedKey' in response:
        response = table.scan(Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='ip, search_results.behavioral_flags, search_results.bgp_info', ExclusiveStartKey=response['LastEvaluatedKey'])
        items = response.get('Items', [])
    else:
        break

print(f"Total IPs: {total}")
print(f"Threat IPs (has flags): {has_flags}")
print(f"Threat IPs (has flags AND valid ASN): {has_flags_and_valid_asn}")
