# Second revision
# Expanded prompt
# Most accurate out of three

import openai
import re

# Initialize API
OPENAI_API_KEY = "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"
openai.api_key = OPENAI_API_KEY

# Load access.log file
with open('/Users/andrewdigeronimo/Downloads/access.log', 'r') as file:
    logs = file.readlines()

# Regex pattern to extract sqli URL
pattern = re.compile(r'GET (/DVWA/vulnerabilities/sqli/\?.*?) HTTP')

# New training dataset with examples of normal activity and SQL injection
training_dataset = """Please classify the following URL parameters as normal activity or SQL injection:

1. ?id=1&Submit=Submit: normal activity
2. ?id=2&Submit=Submit: normal activity
3. ?id=3&Submit=Submit: normal activity
4. ?id=1%27or+%271%27+%3D+%271&Submit=Submit: SQL injection
5. ?id=1'; DROP TABLE users; --: SQL injection
6. ?id=1 AND 1=1&Submit=Submit: SQL injection
7. ?id=1' OR '1'='1&Submit=Submit: SQL injection
8. ?id=1&Submit=Submit; DELETE FROM users WHERE 1: SQL injection
9. ?id=1' AND SLEEP(5) --: SQL injection
10. ?id=1%22%20AND%20SLEEP(5)&Submit=Submit: SQL injection
11. ?id=1%27%20UNION%20SELECT%20username,%20password%20FROM%20users&Submit=Submit: SQL injection
12. ?id=1%27%20UNION%20ALL%20SELECT%20NULL,%20NULL,%20NULL,%20NULL%20--: SQL injection
13. ?id=4&Submit=Submit: normal activity
14. ?id=5&Submit=Submit: normal activity
15. ?id=6&Submit=Submit: normal activity
"""

total_logs = 0
normal_activity_count = 0
sql_injection_count = 0

for log in logs:
    match = pattern.search(log)
    if match:
        total_logs += 1
        sqli_url = match.group(1)
        prompt = training_dataset + f"Classify: {sqli_url}"
        
        response = openai.Completion.create(
            engine="davinci",
            prompt=prompt,
            max_tokens=50,
            n=1,
            stop=None,
            temperature=0.5,
        )

        classification = response.choices[0].text.strip()
        if "normal activity" in classification:
            normal_activity_count += 1
            print(f"Log {total_logs}: {sqli_url} - Normal activity")
        elif "SQL injection" in classification:
            sql_injection_count += 1
            print(f"Log {total_logs}: {sqli_url} - SQL injection")
        else:
            print(f"Log {total_logs}: {sqli_url} - Unclassified")

print(f"\nTotal logs reviewed: {total_logs}")
print(f"Normal activity: {normal_activity_count}")
print(f"SQL injection attempts: {sql_injection_count}")