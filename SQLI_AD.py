# Original program developed and presented in the slides
# Uses Regex for identification and training
# A lot of false positives

import openai
import re

# Initialize API
OPENAI_API_KEY = "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"
openai.api_key = OPENAI_API_KEY

# Load access.log file
with open('/Users/andrewdigeronimo/Downloads/access.log', 'r') as file:
    logs = file.readlines()

# Define the SQL injection pattern for the ID field
id_pattern = r"id=[^&]*('|\"|%27|%22|\bor\b|' OR '1'='1).*&"

def classify_log(log, response_text):
    if "SQL injection" in response_text:
        return "SQL Injection"
    elif "normal activity" in response_text:
        return "Normal activity"
    else:
        return "Unclassified"

# Prepare variables to hold counts and dates
total_logs = len(logs)
sql_injections = 0
normal_activities = 0
unclassified = 0
sql_dates = []

# Check each log entry for SQL injection attempts
for log in logs:
    # Filter logs containing the sqli link and a submission attempt
    if "http://localhost/DVWA/vulnerabilities/sqli/" in log and "Submit=Submit" in log:
        # Check for SQL injection patterns in the ID field
        is_suspicious = re.search(id_pattern, log, re.IGNORECASE)

        # Generate a prompt for OpenAI
        prompt = f"""Analyze the following log entry and determine whether it represents normal activity or an SQL injection attempt. 
                     Look for signs of SQL injection, such as unusual or suspicious values in the query string, or the use of SQL keywords in unexpected places.
                     Normal activity is defined as having only an integer in the submission.
                     Log entry: {log}"""

        # Get OpenAI's prediction
        response = openai.Completion.create(
            engine="davinci",
            prompt=prompt,
            max_tokens=60,
            temperature=0.5,
        )

        # Perform binary classification based on the prediction
        classification = classify_log(log, response.choices[0].text.strip())

        # Print log and prediction
        print(f"Log: {log}")
        print(f"Classification: {classification}\n")

        # Update counts and dates based on classification
        if classification == "SQL Injection":
            sql_injections += 1
            # Extract date from log
            date = re.search(r"\[(.+?)\]", log).group(1)
            sql_dates.append(date)
        elif classification == "Normal activity":
            normal_activities += 1
        else:
            unclassified += 1

# Print summary
print(f"Total logs: {total_logs}")
print(f"SQL Injections: {sql_injections}")
print(f"Normal activities: {normal_activities}")
print(f"Unclassified: {unclassified}")
print("Dates when SQL was detected:")
for date in sql_dates:
    print(date)