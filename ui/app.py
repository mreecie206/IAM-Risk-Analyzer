# ui/app.py

from flask import Flask, render_template_string, request
import json

from src.analyzer import Analyzer

app = Flask(__name__)
analyzer = Analyzer()

# Basic HTML template (inline for starter version)
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>IAM Risk Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        h1 { color: #2c3e50; }
        pre { background: #f4f4f4; padding: 1em; border-radius: 5px; }
        .finding { margin-bottom: 1em; }
        .severity { font-weight: bold; }
    </style>
</head>
<body>
    <h1>IAM Risk Analyzer</h1>
    <form method="POST" enctype="multipart/form-data">
        <label for="config">Upload IAM Config (JSON):</label><br>
        <input type="file" name="config" accept=".json" required>
        <button type="submit">Analyze</button>
    </form>

    {% if report %}
        <h2>Risk Report</h2>
        <p><strong>Total Score:</strong> {{ report.total_score }}</p>

        <h3>By Severity</h3>
        <ul>
        {% for severity, count in report.by_severity.items() %}
            <li>{{ severity.value }}: {{ count }}</li>
        {% endfor %}
        </ul>

        <h3>By NIST Function</h3>
        <ul>
        {% for fn, count in report.by_nist_function.items() %}
            <li>{{ fn }}: {{ count }}</li>
        {% endfor %}
        </ul>

        <h3>Findings</h3>
        {% for f in report.findings %}
            <div class="finding">
                <span class="severity">[{{ f.severity.value }}]</span>
                <strong>{{ f.title }}</strong> (Resource: {{ f.resource_id }}, Score: {{ f.score }})<br>
                {{ f.description }}
            </div>
        {% endfor %}
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    if request.method == "POST":
        file = request.files["config"]
        if file:
            iam_config = json.load(file)
            report = analyzer.analyze(iam_config)
    return render_template_string(TEMPLATE, report=report)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

