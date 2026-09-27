import boto3
import os
from dotenv import load_dotenv

load_dotenv()
dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION'))
table = dynamodb.Table(os.getenv('DYNAMO_TABLE_NAME'))

total = 0
has_flags = 0

response = table.scan(Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='ip, search_results.behavioral_flags')
items = response.get('Items', [])
while True:
    for item in items:
        ip = item.get('ip', '')
        if ip.startswith('__'): continue
        total += 1
        sr = item.get('search_results', {})
        flags = sr.get('behavioral_flags')
        if flags and len(flags) > 0:
            has_flags += 1
    
    if 'LastEvaluatedKey' in response:
        response = table.scan(Select='SPECIFIC_ATTRIBUTES', ProjectionExpression='ip, search_results.behavioral_flags', ExclusiveStartKey=response['LastEvaluatedKey'])
        items = response.get('Items', [])
    else:
        break

print(f"Total IPs: {total}")
print(f"Threat IPs (has flags): {has_flags}")
