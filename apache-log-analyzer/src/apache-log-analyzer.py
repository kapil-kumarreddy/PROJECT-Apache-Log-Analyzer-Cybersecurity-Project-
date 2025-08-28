# ===========================
# Step 1: Import Libraries
# ===========================
import re
import pandas as pd
from collections import Counter
from google.colab import files

# Explanation:
# re         → For regular expressions to parse log lines
# pandas     → For tabular data handling and exporting
# Counter    → For counting IPs and requests
# files      → To upload files directly in Google Colab
# ===========================
# Step 2: Upload Apache Log File
# ===========================
uploaded = files.upload()

# Get the uploaded file name
log_file_path = list(uploaded.keys())[0]

# Explanation:
# files.upload() → Opens a file picker in Colab for you to upload your log file
# log_file_path  → Stores the file name for further use
# ===========================
# Step 3: Function to Read Log File
# ===========================
def read_log(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        return file.readlines()# Read and parse logs
logs = read_log(log_file_path)
print(f"Total log lines: {len(logs)}")

# Explanation:
# We read the file line-by-line and return a list of log entries.
# encoding="utf-8", errors="ignore" → Avoid errors from special characters.
# ===========================
# Step 4: Parse Log Data
# ===========================
def parse_logs(log_lines):
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
    )

    parsed_data = []
    for line in log_lines:
        match = log_pattern.match(line)
        if match:
            parsed_data.append(match.groupdict())

    return pd.DataFrame(parsed_data)

df = parse_logs(logs)
print("Sample parsed data:")
print(df.head())

# Explanation:
# We use a regex pattern to capture:
#   ip       → Visitor IP
#   datetime → Access time
#   method   → HTTP method (GET, POST, etc.)
#   url      → Requested URL
#   status   → HTTP status code (200, 404, etc.)
#   size     → Response size in bytes
# All parsed data is stored in a Pandas DataFrame for analysis.
# ===========================
# Step 5: Analyze Traffic
# ===========================
# Most common IP addresses
top_ips = Counter(df["ip"]).most_common(5)
print("\nTop 5 IP Addresses:")
print(top_ips)

# Most requested URLs
top_urls = Counter(df["url"]).most_common(5)
print("\nTop 5 URLs:")
print(top_urls)

# Status code counts
status_counts = df["status"].value_counts()
print("\nStatus Code Counts:")
print(status_counts)

# Explanation:
# Counter → Quickly counts frequency of each IP and URL.
# value_counts() → Built-in Pandas method for counting values in a column.
# ===========================
# Step 6: Export Analysis to CSV
# ===========================
df.to_csv("parsed_logs.csv", index=False)
files.download("parsed_logs.csv")

# Explanation:
# Save the parsed DataFrame to a CSV file.
# files.download() → Lets you download the file to your local computer.
import matplotlib.pyplot as plt

# Top 5 IPs visualization
top_ips = df['ip'].value_counts().head(5)
plt.figure(figsize=(8, 5))
top_ips.plot(kind='bar', color='skyblue')
plt.title('Top 5 IP Addresses')
plt.xlabel('IP Address')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Top 5 URLs visualization
top_urls = df['url'].value_counts().head(5)
plt.figure(figsize=(8, 5))
top_urls.plot(kind='bar', color='orange')
plt.title('Top 5 Requested URLs')
plt.xlabel('URL')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Status codes visualization
status_counts = df['status'].value_counts()
plt.figure(figsize=(6, 6))
status_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, colors=['green','blue','red','purple','gray'])
plt.title('HTTP Status Code Distribution')
plt.ylabel('')
plt.show()

from collections import defaultdict

# Thresholds for anomaly detection
REQUEST_THRESHOLD = 200  # Example: >200 requests is suspicious
ERROR_THRESHOLD = 10  # Example: >20 errors (404) is suspicious

# 1. Detect IPs with high request volume
high_traffic_ips = df['ip'].value_counts()

suspicious_traffic = high_traffic_ips[high_traffic_ips > REQUEST_THRESHOLD]

# 2. Detect IPs with high error counts
error_df = df[df['status'] == "404"]

error_ips = error_df['ip'].value_counts()
suspicious_errors = error_ips[error_ips > ERROR_THRESHOLD]



# 3. Detect access to restricted URLs
restricted_keywords = ['admin', 'login', 'config', 'wp-admin']
restricted_access = df[df['url'].str.contains('|'.join(restricted_keywords), case=False, na=False)]

# Printing results
print("\n🚨 Suspicious IPs (High Traffic):")
print(suspicious_traffic)

print("\n🚨 Suspicious IPs (High Errors):")
print(suspicious_errors)

print("\n🚨 Restricted Access Attempts:")
print(restricted_access[['ip', 'url', 'status']])

import re

# Updated regex to capture user-agent
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
)

# Read and parse logs
records = []
with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            records.append(match.groupdict())

import pandas as pd
dg = pd.DataFrame(records)

# Now we can count user agents
user_agents = dg['user_agent'].value_counts()
print("Top 10 User Agents:")
print(user_agents.head(10))

# Detect suspicious short user agents
suspicious_agents = dg[dg['user_agent'].str.len() < 10]['user_agent'].unique()
print("\nSuspicious User Agents:")
print(suspicious_agents)

# Install geoip2
!pip install geoip2

import geoip2.database
import pandas as pd

# Download MaxMind GeoLite2 database (City or Country)
!wget https://git.io/GeoLite2-Country.mmdb -O GeoLite2-Country.mmdb
# Initialize the GeoIP reader
reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

# Function to get country for an IP
def get_country(ip):
    try:
        response = reader.country(ip)
        return response.country.name
    except:
        return "Unknown"

# Apply to suspicious IPs or top IPs
df['country'] = df['ip'].apply(get_country)

# Example: See top 10 countries by request volume
print(df['country'].value_counts().head(10))
print(df[df['ip'].isin(suspicious_traffic)]['country'].value_counts())
# Prepare result with geo-location
results = []
for ip, count in suspicious_traffic.items():
    try:
        country = reader.country(ip).country.name
    except:
        country = "Unknown"
    results.append((ip, count, country))
# Create DataFrame for neat display
suspicious_df = pd.DataFrame(results, columns=['IP Address', 'Request Count', 'Country'])
print("🚨 Suspicious IPs with Geo Location:")
print(suspicious_df)
# Close GeoIP reader
reader.close()
#Step 6: Time-based Attack Analysis (Detect DoS / Brute Force)
import matplotlib.pyplot as plt

# Make sure we actually parse the time column from raw log
# If your dataframe already has a column like "timestamp", use that instead of 'time'
df['datetime'] = pd.to_datetime(df['datetime'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')

# Drop rows where parsing failed
df = df.dropna(subset=['datetime'])

# Group by IP and minute
traffic_time = df.groupby([df['ip'], df['datetime'].dt.floor('T')]).size().reset_index(name='requests')

# Threshold (requests per minute from one IP)
THRESHOLD = 50
suspicious_traffic = traffic_time[traffic_time['requests'] > THRESHOLD]

print("🚨 Suspicious Time-based Traffic (Possible DoS/Brute Force):")
print(suspicious_traffic.head(20))

# Visualization
if not suspicious_traffic.empty:
    top_ip = suspicious_traffic['ip'].iloc[0]
    ip_data = traffic_time[traffic_time['ip'] == top_ip]

    plt.figure(figsize=(12,6))
    plt.plot(ip_data['datetime'], ip_data['requests'], marker='o')
    plt.title(f"Requests per Minute for {top_ip}")
    plt.xlabel("Time")
    plt.ylabel("Number of Requests")
    plt.xticks(rotation=45)
    plt.show()
else:
    print("✅ No suspicious time-based traffic detected.")

# Step 7: Suspicious URL / Path Analysis

# Common suspicious patterns
suspicious_patterns = [
    r"\.\./",        # Directory traversal
    r"\.php",        # PHP exploitation attempts
    r"\.asp",        # ASP exploitation attempts
    r"select.+from", # SQL injection
    r"union.+select",# SQL injection
    r"admin",        # Admin panel probing
    r"wp-",          # WordPress attack attempts
    r"config",       # Sensitive file
    r"\.exe",        # Executable files
    r"\.sh"          # Shell scripts
]

# Check URLs for suspicious patterns
import re
sus_urls = df[df['url'].str.contains('|'.join(suspicious_patterns), case=False, na=False)]

print("🚨 Suspicious URLs detected:")
print(sus_urls[['ip', 'datetime', 'url']].head(20))

# Step 8: Frequency Analysis of Suspicious Requests

# Count suspicious URLs
url_counts = sus_urls['url'].value_counts().head(10)
print("🔎 Top 10 suspicious URLs requested:")
print(url_counts)

# Count IPs making suspicious requests
ip_counts = sus_urls['ip'].value_counts().head(10)
print("\n🔎 Top 10 IPs making suspicious requests:")
print(ip_counts)
import re

# --- Pick the right column names safely ---
time_col = 'datetime' if 'datetime' in df.columns else ('time' if 'time' in df.columns else None)
if time_col is None:
    raise ValueError("No timestamp column found. Expected 'datetime' or 'time'.")

status_col = 'status' if 'status' in df.columns else ('status_code' if 'status_code' in df.columns else None)
if status_col is None:
    raise ValueError("No status column found. Expected 'status' or 'status_code'.")

# If method/url missing but you have a raw request line, extract them
if ('method' not in df.columns or 'url' not in df.columns) and 'request' in df.columns:
    req_parts = df['request'].astype(str).str.extract(r'^(\S+)\s+(\S+)(?:\s+(\S+))?$')
    if 'method' not in df.columns:
        df['method'] = req_parts[0].fillna('-')
    if 'url' not in df.columns:
        df['url'] = req_parts[1].fillna('-')
    if 'protocol' not in df.columns:
        df['protocol'] = req_parts[2]

# If still missing, create placeholders so printing doesn’t crash
if 'method' not in df.columns:
    df['method'] = '-'
if 'url' not in df.columns:
    df['url'] = '-'

# --- Choose a target IP robustly (prefer the most active in suspicious URLs, else overall) ---
if 'sus_urls' in globals() and not sus_urls.empty:
    target_ip = sus_urls['ip'].value_counts().idxmax()
else:
    target_ip = df['ip'].value_counts().idxmax()

print(f"🔎 Analyzing session for IP: {target_ip}")

# --- Filter and sort by time for a readable session view ---
session = df[df['ip'] == target_ip].sort_values(by=time_col)

# Show first 20 requests from this IP
print(session[[time_col, 'method', 'url', status_col]].head(20))
print(df.columns.tolist())
# Step 9: Session Analysis (tracking a single IP's behavior)

# Pick a suspicious IP (for demo, top one from previous suspicious URLs step)
target_ip = sus_urls['ip'].value_counts().index[0]
print(f"🔎 Analyzing session for IP: {target_ip}")

# Filter all requests from this IP
session = df[df['ip'] == target_ip]

# Show first 20 requests
print(session[['datetime', 'method', 'url', 'status']].head(20))

# --- Extra Analysis ---
# 1. Status code distribution for this IP
print("\n📊 Status code distribution:")
print(session['status'].value_counts())

# 2. Top 10 URLs accessed by this IP
print("\n🌐 Top 10 URLs accessed:")
print(session['url'].value_counts().head(10))

# 3. Timeline of requests (optional visualization)
import matplotlib.pyplot as plt

session['datetime'] = pd.to_datetime(session['datetime'], errors='coerce')
session = session.dropna(subset=['datetime'])

plt.figure(figsize=(12,5))
session.set_index('datetime').resample('1T').size().plot()
plt.title(f"Request Timeline for IP: {target_ip}")
plt.xlabel("Time (minute)")
plt.ylabel("Number of Requests")
plt.show()

# Step 10: Correlation & Attack Pattern Detection

# 1. Multiple IPs hitting the same URL
url_ip_map = df.groupby('url')['ip'].nunique().sort_values(ascending=False)
print("🔗 URLs accessed by the most unique IPs:")
print(url_ip_map.head(10))

# 2. IPs with repeated errors across multiple URLs
error_df = df[df['status'].astype(str).str.startswith("4")]  # all 4xx errors
ip_error_map = error_df.groupby('ip')['url'].nunique().sort_values(ascending=False)
print("\n⚠️ IPs causing errors across multiple URLs:")
print(ip_error_map.head(10))

import matplotlib.pyplot as plt
import seaborn as sns

# 1. Top 10 IPs by request volume
top_ips = df['ip'].value_counts().head(10)
plt.figure(figsize=(10,5))
sns.barplot(x=top_ips.values, y=top_ips.index, palette="viridis")
plt.title("Top 10 IPs by Number of Requests")
plt.xlabel("Request Count")
plt.ylabel("IP Address")
plt.show()

# 2. Top 10 URLs accessed
top_urls = df['url'].value_counts().head(10)
plt.figure(figsize=(10,5))
sns.barplot(x=top_urls.values, y=top_urls.index, palette="magma")
plt.title("Top 10 Accessed URLs")
plt.xlabel("Access Count")
plt.ylabel("URL")
plt.show()

# 3. Status code distribution
plt.figure(figsize=(8,5))
sns.countplot(x='status', data=df, palette="Set2", order=df['status'].value_counts().index)
plt.title("HTTP Status Code Distribution")
plt.xlabel("Status Code")
plt.ylabel("Count")
plt.show()

# 4. Requests over time (trend)
df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
df.set_index('datetime', inplace=True)
df.resample('1H').size().plot(figsize=(12,6), color="blue")
plt.title("Request Volume Over Time (Hourly)")
plt.xlabel("Time")
plt.ylabel("Number of Requests")
plt.show()

# Install ReportLab
!pip install reportlab

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet


# === Export to CSV ===
df.to_csv("full_log_analysis.csv", index=False)

# Export suspicious findings
suspicious_traffic.to_csv("suspicious_ips.csv")
suspicious_errors.to_csv("suspicious_errors.csv")
sus_urls.to_csv("suspicious_urls.csv", index=False)

print("✅ Exported: full_log_analysis.csv, suspicious_ips.csv, suspicious_ips_and_errors.csv, suspicious_urls.csv")


# === Export to PDF Report ===
pdf_report = "log_analysis_report.pdf"
doc = SimpleDocTemplate(pdf_report, pagesize=letter)
styles = getSampleStyleSheet()
story = []

# Title
story.append(Paragraph("🔎 Apache Log Security Analysis Report", styles['Title']))
story.append(Spacer(1, 12))

# Suspicious IPs
story.append(Paragraph("🚨 Suspicious IPs", styles['Heading2']))
if not suspicious_traffic.empty:
    data = [["IP", "Request Count"]] + suspicious_traffic.reset_index().values.tolist()
    table = Table(data)
    story.append(table)
else:
    story.append(Paragraph("No suspicious traffic detected.", styles['Normal']))
story.append(Spacer(1, 12))

story.append(Paragraph("🚨 Suspicious errors", styles['Heading2']))
if not suspicious_errors.empty:
    data = [["IP", "Request Count"]] + suspicious_errors.reset_index().values.tolist()
    table = Table(data)
    story.append(table)
else:
    story.append(Paragraph("No suspicious errors detected.", styles['Normal']))
story.append(Spacer(1, 12))


from reportlab.platypus import TableStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors

# Suspicious URLs Section (centered)
story.append(Paragraph(" Suspicious URLs", styles['Normal']))

if not sus_urls.empty:
    data = [["URL", "Count"]] + sus_urls.reset_index().values.tolist()
    table = Table(data, hAlign="CENTER")
    table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    story.append(table)
else:
    story.append(Paragraph("No suspicious URLs detected.", styles['CenteredNormal']))

# Status Code Distribution
story.append(Paragraph("📊 Status Code Distribution", styles['Heading2']))
status_counts = df['status'].value_counts().reset_index()
status_counts.columns = ["Status", "Count"]
data = [["Status", "Count"]] + status_counts.values.tolist()
table = Table(data)
story.append(table)
story.append(Spacer(1, 12))

# GeoIP Country Counts
story.append(Paragraph("🌍 Top Countries", styles['Heading2']))
country_counts = df['country'].value_counts().head(10).reset_index()
country_counts.columns = ["Country", "Count"]
data = [["Country", "Count"]] + country_counts.values.tolist()
table = Table(data)
story.append(table)
story.append(Spacer(1, 12))

# Build PDF
doc.build(story)
print("✅ PDF report generated successfully: log_analysis_report.pdf")
